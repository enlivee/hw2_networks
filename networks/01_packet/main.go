package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

func parseHexDump(data []byte) ([]byte, error) {
	clean := make([]byte, 0, len(data))
	for i, c := range data {
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ':':
			continue
		case isHexChar(c):
			clean = append(clean, c)
		default:
			return nil, fmt.Errorf("недопустимый символ %q на позиции %d", c, i)
		}
	}
	return hex.DecodeString(string(clean))
}

func isHexChar(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'f') ||
		(b >= 'A' && b <= 'F')
}

// разбирает кадр
func parseEthernet(frame []byte, w io.Writer) error {
	if len(frame) < 14 {
		return fmt.Errorf("кадр короче заголовка Ethernet: %d байт", len(frame))
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	fmt.Fprintf(w, "eth.dst %s\n", net.HardwareAddr(frame[0:6]))
	fmt.Fprintf(w, "eth.src %s\n", net.HardwareAddr(frame[6:12]))
	fmt.Fprintf(w, "eth.ethertype 0x%04x\n", etherType)

	if etherType == 0x0800 { // 0x86dd IPv6, 0x0806 ARP
		return parseIPv4(frame[14:], w)
	}
	return nil
}

func parseIPv4(b []byte, w io.Writer) error {
	if len(b) < 20 {
		return fmt.Errorf("заголовок IPv4 короче 20 байт: %d", len(b))
	}
	version := b[0] >> 4
	if version != 4 {
		return fmt.Errorf("ожидалась версия IP 4, в пакете %d", version)
	}
	ihl := int(b[0]&0x0F) * 4
	if ihl < 20 || ihl > len(b) {
		return fmt.Errorf("некорректный ihl: %d", ihl)
	}
	totalLength := int(binary.BigEndian.Uint16(b[2:4]))
	if totalLength < ihl {
		return fmt.Errorf("total_length %d меньше ihl %d", totalLength, ihl)
	}
	payloadLen := totalLength - ihl // длина всего, что идёт после IP-заголовка

	fl := binary.BigEndian.Uint16(b[6:8])
	proto := b[9]

	var transport func() error
	if fl&0x1FFF == 0 {
		switch proto {
		case 6:
			transport = func() error { return parseTCP(b[ihl:], payloadLen, w) }
		case 17:
			transport = func() error { return parseUDP(b[ihl:], payloadLen, w) }
		}
	}
	var flags string
	switch {
	case fl&0x4000 != 0 && fl&0x2000 != 0:
		flags = "DF,MF"
	case fl&0x4000 != 0:
		flags = "DF"
	case fl&0x2000 != 0:
		flags = "MF"
	default:
		flags = "none"
	}

	fmt.Fprintf(w, "ip.version %d\n", version)
	fmt.Fprintf(w, "ip.ihl_bytes %d\n", ihl)
	fmt.Fprintf(w, "ip.total_length %d\n", totalLength)
	fmt.Fprintf(w, "ip.id 0x%04x\n", binary.BigEndian.Uint16(b[4:6]))
	fmt.Fprintf(w, "ip.flags %s\n", flags)
	fmt.Fprintf(w, "ip.frag_offset %d\n", int(fl&0x1FFF)*8)
	fmt.Fprintf(w, "ip.ttl %d\n", b[8])
	fmt.Fprintf(w, "ip.protocol %d\n", proto)
	fmt.Fprintf(w, "ip.src %d.%d.%d.%d\n", b[12], b[13], b[14], b[15])
	fmt.Fprintf(w, "ip.dst %d.%d.%d.%d\n", b[16], b[17], b[18], b[19])
	fmt.Fprintf(w, "ip.checksum_valid %t\n", checksumValid(b, ihl))

	if transport != nil {
		return transport()
	}
	fmt.Fprintf(w, "payload.length %d\n", payloadLen)
	return nil
}

func checksumValid(b []byte, headerLen int) bool {
	var sum uint32
	for i := 0; i < headerLen; i += 2 {
		if i == 10 { // само поле checksum считаем нулём
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum) == binary.BigEndian.Uint16(b[10:12])
}

// seg это всё после IP-заголовка, ipPayload это total_length - ihl.
func parseTCP(seg []byte, ipPayload int, w io.Writer) error {
	if len(seg) < 20 {
		return fmt.Errorf("сегмент TCP короче 20 байт: %d", len(seg))
	}
	dataOffset := int(seg[12]>>4) * 4
	if dataOffset < 20 || dataOffset > len(seg) {
		return fmt.Errorf("некорректный tcp data offset: %d байт", dataOffset)
	}
	if ipPayload < dataOffset {
		return fmt.Errorf("total_length не вмещает заголовок TCP (%d < %d)", ipPayload, dataOffset)
	}

	fmt.Fprintf(w, "tcp.src_port %d\n", binary.BigEndian.Uint16(seg[0:2]))
	fmt.Fprintf(w, "tcp.dst_port %d\n", binary.BigEndian.Uint16(seg[2:4]))
	fmt.Fprintf(w, "tcp.seq %d\n", binary.BigEndian.Uint32(seg[4:8]))
	fmt.Fprintf(w, "tcp.ack %d\n", binary.BigEndian.Uint32(seg[8:12]))
	fmt.Fprintf(w, "tcp.data_offset_bytes %d\n", dataOffset)
	fmt.Fprintf(w, "tcp.flags %s\n", tcpFlags(seg[13]))
	fmt.Fprintf(w, "tcp.window %d\n", binary.BigEndian.Uint16(seg[14:16]))
	fmt.Fprintf(w, "payload.length %d\n", ipPayload-dataOffset)
	return nil
}

func tcpFlags(b byte) string {
	names := []struct {
		mask byte
		name string
	}{
		{0x01, "FIN"}, {0x02, "SYN"}, {0x04, "RST"},
		{0x08, "PSH"}, {0x10, "ACK"}, {0x20, "URG"},
	}
	var parts []string
	for _, f := range names {
		if b&f.mask != 0 {
			parts = append(parts, f.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

func parseUDP(seg []byte, ipPayload int, w io.Writer) error {
	const udpHeaderLen = 8
	if len(seg) < udpHeaderLen {
		return fmt.Errorf("датаграмма UDP короче 8 байт: %d", len(seg))
	}
	if ipPayload < udpHeaderLen {
		return fmt.Errorf("total_length не вмещает заголовок UDP (%d < 8)", ipPayload)
	}

	fmt.Fprintf(w, "udp.src_port %d\n", binary.BigEndian.Uint16(seg[0:2]))
	fmt.Fprintf(w, "udp.dst_port %d\n", binary.BigEndian.Uint16(seg[2:4]))
	fmt.Fprintf(w, "udp.length %d\n", binary.BigEndian.Uint16(seg[4:6]))
	fmt.Fprintf(w, "payload.length %d\n", ipPayload-udpHeaderLen)
	return nil
}

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка чтения stdin:", err)
		os.Exit(1)
	}
	frame, err := parseHexDump(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad input:", err)
		os.Exit(1)
	}

	// печатаем только после полного разбора
	var out bytes.Buffer
	if err := parseEthernet(frame, &out); err != nil {
		fmt.Fprintln(os.Stderr, "malformed frame:", err)
		os.Exit(1)
	}
	os.Stdout.Write(out.Bytes())
}
