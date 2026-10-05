package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"time"
)

var qtypes = map[string]uint16{
	"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28,
}

type Record struct {
	Type  string
	Value string
	TTL   uint32
}

type cacheEntry struct {
	records []Record
	expires time.Time
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "Usage: dns <server> <port>")
		os.Exit(1)
	}
	server := net.JoinHostPort(os.Args[1], os.Args[2])
	cache := map[string]cacheEntry{}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			fmt.Fprintln(os.Stderr, "Bad line:", line)
			continue
		}
		name, typeStr := fields[0], fields[1]
		qtype, ok := qtypes[strings.ToUpper(typeStr)]
		if !ok {
			fmt.Fprintln(os.Stderr, "Unsupported type:", typeStr)
			continue
		}

		fmt.Printf("query %s %s\n", name, typeStr)

		key := strings.TrimSuffix(strings.ToLower(name), ".") + "/" + strings.ToUpper(typeStr)

		// 1. Кеш
		if e, found := cache[key]; found {
			if time.Now().Before(e.expires) {
				fmt.Println("status NOERROR")
				printRecords(e.records)
				fmt.Println("end")
				continue
			}
			delete(cache, key)
		}

		// 2. Запрос по сети
		id := uint16(rand.Uint32())
		resp, ok := exchange(server, id, buildQuery(id, name, qtype))
		if !ok {
			fmt.Println("status TIMEOUT")
			fmt.Println("end")
			os.Exit(1)
		}

		rcode, recs, ok := parseResponse(resp)
		if !ok {
			fmt.Fprintln(os.Stderr, "Malformed response")
			fmt.Println("status SERVFAIL")
			fmt.Println("end")
			continue
		}

		fmt.Println("status " + rcodeName(rcode))
		printRecords(recs)
		fmt.Println("end")

		// 3. Кеширование: только NOERROR, есть записи, минимальный TTL > 0
		if rcode == 0 && len(recs) > 0 {
			minTTL := recs[0].TTL
			for _, r := range recs {
				if r.TTL < minTTL {
					minTTL = r.TTL
				}
			}
			if minTTL > 0 {
				cache[key] = cacheEntry{
					records: recs,
					expires: time.Now().Add(time.Duration(minTTL) * time.Second),
				}
			}
		}
	}
}

func printRecords(recs []Record) {
	for _, r := range recs {
		fmt.Printf("answer %s %s %d\n", r.Type, r.Value, r.TTL)
	}
}

func rcodeName(code int) string {
	switch code {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 5:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE%d", code)
}

func buildQuery(id uint16, name string, qtype uint16) []byte {
	var msg []byte

	// Заголовок
	msg = binary.BigEndian.AppendUint16(msg, id)
	msg = binary.BigEndian.AppendUint16(msg, 0x0100) // флаги: RD
	msg = binary.BigEndian.AppendUint16(msg, 1)      // вопросов: 1
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)

	// Имя
	name = strings.TrimSuffix(name, ".")
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)

	// Тип и класс
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, 1) // IN
	return msg
}

func exchange(server string, id uint16, req []byte) ([]byte, bool) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error connecting to server:", err)
		return nil, false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(req); err != nil {
		fmt.Fprintln(os.Stderr, "Error sending request:", err)
		return nil, false
	}

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading response:", err)
			return nil, false
		}
		if n < 12 {
			continue
		}
		if binary.BigEndian.Uint16(buf[0:2]) != id {
			continue
		}
		return buf[:n], true
	}
}

// Читает имя с позиции off. Возвращает имя с точкой в конце и позицию после имени.
func parseName(msg []byte, off int) (string, int) {
	var name string
	next := -1
	for i := 0; i < 100; i++ {
		b := msg[off]
		switch {
		case b == 0:
			if next == -1 {
				next = off + 1
			}
			if name == "" {
				name = "."
			}
			return name, next
		case b&0xC0 == 0xC0:
			ptr := int(b&0x3F)<<8 | int(msg[off+1])
			if next == -1 {
				next = off + 2
			}
			off = ptr
		default:
			name += string(msg[off+1:off+1+int(b)]) + "."
			off += int(b) + 1
		}
	}
	return name, next
}

func parseResponse(msg []byte) (rcode int, records []Record, ok bool) {
	// при выходе за границы сообщения считаем ответ битым
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()

	flags := binary.BigEndian.Uint16(msg[2:4])
	rcode = int(flags & 0x000F)
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))

	off := 12
	for i := 0; i < qdCount; i++ {
		_, off = parseName(msg, off)
		off += 4 // тип и класс
	}

	for i := 0; i < anCount; i++ {
		_, off = parseName(msg, off)
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
		rdLength := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		rdStart := off + 10

		typeName, value, supported := formatRData(msg, typ, rdStart, rdLength)
		if supported {
			records = append(records, Record{Type: typeName, Value: value, TTL: ttl})
		}
		off = rdStart + rdLength
	}
	return rcode, records, true
}

func formatRData(msg []byte, typ uint16, start, length int) (string, string, bool) {
	switch typ {
	case 1: // A
		b := msg[start : start+4]
		return "A", fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]), true

	case 2: // NS
		name, _ := parseName(msg, start)
		return "NS", name, true

	case 5: // CNAME
		name, _ := parseName(msg, start)
		return "CNAME", name, true

	case 15: // MX
		priority := binary.BigEndian.Uint16(msg[start : start+2])
		name, _ := parseName(msg, start+2)
		return "MX", fmt.Sprintf("%d %s", priority, name), true

	case 16: // TXT
		var txt strings.Builder
		for pos := start; pos < start+length; {
			l := int(msg[pos])
			txt.Write(msg[pos+1 : pos+1+l])
			pos += 1 + l
		}
		return "TXT", txt.String(), true

	case 28: // AAAA
		var g [8]uint16
		for i := 0; i < 8; i++ {
			g[i] = binary.BigEndian.Uint16(msg[start+i*2 : start+i*2+2])
		}
		return "AAAA", formatIPv6(g), true
	}
	return "", "", false // неподдерживаемый тип пропускаем
}

func formatIPv6(g [8]uint16) string {
	// самая длинная цепочка нулевых групп (при равенстве берётся первая)
	bestStart, bestLen := -1, 0
	for i := 0; i < 8; {
		if g[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && g[j] == 0 {
			j++
		}
		if j-i > bestLen {
			bestStart, bestLen = i, j-i
		}
		i = j
	}
	if bestLen < 2 { // одиночный ноль не сжимается (RFC 5952)
		bestStart = -1
	}

	join := func(from, to int) string {
		parts := make([]string, 0, 8)
		for i := from; i < to; i++ {
			parts = append(parts, fmt.Sprintf("%x", g[i]))
		}
		return strings.Join(parts, ":")
	}

	if bestStart == -1 {
		return join(0, 8)
	}
	return join(0, bestStart) + "::" + join(bestStart+bestLen, 8)
}
