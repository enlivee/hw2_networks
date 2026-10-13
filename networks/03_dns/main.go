package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	statusBadQuery  = "BADQUERY"  // входная строка не годится, в сеть не ходили
	statusMalformed = "MALFORMED" // сервер ответил, но ответ не разбирается
)

var qtypes = map[string]uint16{
	"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28,
}

var errTruncated = errors.New("сообщение обрезано")

type record struct {
	Type  string
	Value string
	TTL   uint32
}

type response struct {
	rcode   int
	records []record // только поддерживаемые типы
	minTTL  uint32   // минимум по всем записям раздела ответа
}

type cacheEntry struct {
	records []record
	expires time.Time
}

func finish(status string) {
	fmt.Println("status " + status)
	fmt.Println("end")
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
			fmt.Printf("query %s\n", line)
			finish(statusBadQuery)
			continue
		}
		name, typeStr := fields[0], fields[1]
		fmt.Printf("query %s %s\n", name, typeStr)

		qtype, ok := qtypes[strings.ToUpper(typeStr)]
		if !ok {
			fmt.Fprintln(os.Stderr, "unsupported type:", typeStr)
			finish(statusBadQuery)
			continue
		}
		wireName, err := encodeName(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad name %q: %v\n", name, err)
			finish(statusBadQuery)
			continue
		}

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
		id, err := randomID()
		if err != nil {
			fmt.Fprintln(os.Stderr, "crypto/rand:", err)
			os.Exit(1)
		}
		raw, err := exchange(server, id, wireName, qtype)
		if err != nil {
			fmt.Fprintln(os.Stderr, "exchange:", err)
			finish("TIMEOUT")
			os.Exit(1)
		}

		resp, err := parseResponse(raw)
		if err != nil {
			// Сервер ответил, но разобрать ответ мы не смогли.
			fmt.Fprintln(os.Stderr, "malformed response:", err)
			finish(statusMalformed)
			continue
		}

		fmt.Println("status " + rcodeName(resp.rcode))
		printRecords(resp.records)
		fmt.Println("end")

		// 3. Кеширование: только NOERROR, есть записи, минимальный TTL > 0
		if resp.rcode == 0 && len(resp.records) > 0 && resp.minTTL > 0 {
			cache[key] = cacheEntry{
				records: resp.records,
				expires: time.Now().Add(time.Duration(resp.minTTL) * time.Second),
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "stdin:", err)
		os.Exit(1)
	}
}

func printRecords(recs []record) {
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

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// encodeName переводит имя в wire-формат и проверяет его по RFC 1035.
func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" { // корень: один нулевой байт
		return []byte{0}, nil
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return nil, errors.New("пустая метка")
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("метка длиннее 63 байт: %d", len(label))
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	if len(out) > 255 {
		return nil, fmt.Errorf("имя длиннее 255 байт: %d", len(out))
	}
	return out, nil
}

func buildQuery(id uint16, wireName []byte, qtype uint16) []byte {
	msg := make([]byte, 0, 12+len(wireName)+4)
	msg = binary.BigEndian.AppendUint16(msg, id)
	msg = binary.BigEndian.AppendUint16(msg, 0x0100) // флаги: RD
	msg = binary.BigEndian.AppendUint16(msg, 1)      // вопросов: 1
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = append(msg, wireName...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, 1) // IN
	return msg
}

func exchange(server string, id uint16, wireName []byte, qtype uint16) ([]byte, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(buildQuery(id, wireName, qtype)); err != nil {
		return nil, err
	}

	// имя, которое мы спрашивали, в том виде, как его вернёт parseName
	qname, _, err := parseName(wireName, 0)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		// копия, чтобы за пределами len не лежало содержимое прошлых пакетов
		msg := append([]byte(nil), buf[:n]...)
		if isAnswerTo(msg, id, qname, qtype) {
			return msg, nil
		}
		// не наш пакет: чужой ID, не ответ, другой вопрос. Ждём дальше.
	}
}

// isAnswerTo проверяет ID, бит QR и совпадение секции вопроса с отправленной.
func isAnswerTo(msg []byte, id uint16, qname string, qtype uint16) bool {
	if len(msg) < 12 {
		return false
	}
	if binary.BigEndian.Uint16(msg[0:2]) != id {
		return false
	}
	if msg[2]&0x80 == 0 { // QR = 0: это запрос, а не ответ
		return false
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return false
	}
	name, off, err := parseName(msg, 12)
	if err != nil || off+4 > len(msg) {
		return false
	}
	return strings.EqualFold(name, qname) &&
		binary.BigEndian.Uint16(msg[off:off+2]) == qtype &&
		binary.BigEndian.Uint16(msg[off+2:off+4]) == 1
}

// parseName читает имя с позиции off. Возвращает имя с точкой в конце
// и позицию сразу после имени в исходном потоке (до указателя, если он был).
func parseName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	next := -1
	jumps := 0
	wireLen := 1 // завершающий нулевой байт

	for {
		if off < 0 || off >= len(msg) {
			return "", 0, errTruncated
		}
		b := msg[off]
		switch b & 0xC0 {
		case 0x00:
			if b == 0 {
				if next == -1 {
					next = off + 1
				}
				if sb.Len() == 0 {
					return ".", next, nil
				}
				return sb.String(), next, nil
			}
			l := int(b)
			if off+1+l > len(msg) {
				return "", 0, errTruncated
			}
			wireLen += 1 + l
			if wireLen > 255 {
				return "", 0, errors.New("имя длиннее 255 байт")
			}
			sb.Write(msg[off+1 : off+1+l])
			sb.WriteByte('.')
			off += 1 + l
		case 0xC0:
			if off+2 > len(msg) {
				return "", 0, errTruncated
			}
			if next == -1 {
				next = off + 2
			}
			jumps++
			if jumps > 100 {
				return "", 0, errors.New("слишком много указателей сжатия")
			}
			off = int(b&0x3F)<<8 | int(msg[off+1])
		default: // 0x40 и 0x80 зарезервированы
			return "", 0, fmt.Errorf("зарезервированный тип метки 0x%02x", b&0xC0)
		}
	}
}

func parseResponse(msg []byte) (*response, error) {
	if len(msg) < 12 {
		return nil, errTruncated
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	resp := &response{rcode: int(flags & 0x000F)}

	var err error
	off := 12
	for i := 0; i < qdCount; i++ {
		if _, off, err = parseName(msg, off); err != nil {
			return nil, err
		}
		off += 4 // тип и класс
		if off > len(msg) {
			return nil, errTruncated
		}
	}

	for i := 0; i < anCount; i++ {
		if _, off, err = parseName(msg, off); err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errTruncated
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
		if ttl&0x80000000 != 0 { // RFC 2181, 8: старший бит взведён, считаем TTL нулём
			ttl = 0
		}
		rdStart := off + 10
		rdEnd := rdStart + int(binary.BigEndian.Uint16(msg[off+8:off+10]))
		if rdEnd > len(msg) {
			return nil, errTruncated
		}

		if i == 0 || ttl < resp.minTTL {
			resp.minTTL = ttl
		}

		typeName, value, supported, err := formatRData(msg, typ, rdStart, rdEnd)
		if err != nil {
			return nil, err
		}
		if supported {
			resp.records = append(resp.records, record{Type: typeName, Value: value, TTL: ttl})
		}
		off = rdEnd
	}
	return resp, nil
}

// formatRData разбирает rdata в msg[start:end]. Неподдерживаемый тип не ошибка.
func formatRData(msg []byte, typ uint16, start, end int) (typeName, value string, supported bool, err error) {
	length := end - start
	switch typ {
	case 1: // A
		if length != 4 {
			return "", "", false, fmt.Errorf("A: rdlength %d, ожидалось 4", length)
		}
		b := msg[start:end]
		return "A", fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]), true, nil

	case 2, 5: // NS, CNAME
		name, next, err := parseName(msg, start)
		if err != nil {
			return "", "", false, err
		}
		if next > end {
			return "", "", false, errors.New("имя выходит за пределы rdata")
		}
		if typ == 2 {
			return "NS", name, true, nil
		}
		return "CNAME", name, true, nil

	case 15: // MX
		if length < 3 {
			return "", "", false, fmt.Errorf("MX: rdlength %d слишком мал", length)
		}
		priority := binary.BigEndian.Uint16(msg[start : start+2])
		name, next, err := parseName(msg, start+2)
		if err != nil {
			return "", "", false, err
		}
		if next > end {
			return "", "", false, errors.New("имя выходит за пределы rdata")
		}
		return "MX", fmt.Sprintf("%d %s", priority, name), true, nil

	case 16: // TXT
		var txt strings.Builder
		for pos := start; pos < end; {
			l := int(msg[pos])
			if pos+1+l > end {
				return "", "", false, errors.New("TXT: строка не помещается в rdata")
			}
			txt.Write(msg[pos+1 : pos+1+l])
			pos += 1 + l
		}
		return "TXT", txt.String(), true, nil

	case 28: // AAAA
		if length != 16 {
			return "", "", false, fmt.Errorf("AAAA: rdlength %d, ожидалось 16", length)
		}
		var g [8]uint16
		for i := range g {
			g[i] = binary.BigEndian.Uint16(msg[start+i*2 : start+i*2+2])
		}
		return "AAAA", formatIPv6(g), true, nil
	}
	return "", "", false, nil // неподдерживаемый тип пропускаем
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
