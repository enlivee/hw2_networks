package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// пример вот
// 001b213c4d5e 0025645d1e22 0800 ethernet
// и 0800 это IPv4 
// 4500003c1c46400040 06 00000a000002 5db8d822 
// 06 это tcp, 17 это udp
// a86a0050 12345678 00000000 a002faf0 00000000

func readAllAndClean(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(data))
	for _, b := range data {
		if isHexChar(b) {
			out = append(out, b)
		}
	}
	dst := make([]byte, hex.DecodedLen(len(out)))
	_, err = hex.Decode(dst, out)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func isHexChar(b byte) bool {
    return (b >= '0' && b <= '9') ||
        (b >= 'a' && b <= 'f') ||
        (b >= 'A' && b <= 'F')
}

func Ethernet() {
	bytes, _ := readAllAndClean(os.Stdin)
	i := 0
	macDestination := strings.Builder{}
	for i < 6 {
		macDestination.WriteString(fmt.Sprintf("%02x:", bytes[i]))
		i++
		macDestination.WriteString(fmt.Sprintf("%02x", bytes[i]))
		i++
		if i != 6 {
			macDestination.WriteString(fmt.Sprint(":"))
		}
	}
	macSource := strings.Builder{}
	for i < 12 {
		macSource.WriteString(fmt.Sprintf("%02x:", bytes[i]))
		i++
		macSource.WriteString(fmt.Sprintf("%02x", bytes[i]))
		i++
		if i != 12 {
			macSource.WriteString(fmt.Sprint(":"))
		}
	}
	etherType := binary.BigEndian.Uint16(bytes[12:14])
	fmt.Printf("eth.dst %s\n", macDestination.String())
	fmt.Printf("eth.src %s\n", macSource.String())
	fmt.Printf("eth.ethertype 0x%04x\n", etherType)

	if etherType == 0x0800 { // 0x86dd IPv6 0x0806 ARP
		IPv4(bytes[14:])
	}

}

func IPv4(b []byte) {
	version := b[0] >> 4
	ihl := (b[0] & 0x0F) * 4
	fmt.Printf("ip.version %d\n", version)
	fmt.Printf("ip.ihl_bytes %d\n", ihl)
	fmt.Printf("ip.total_length %d\n", binary.BigEndian.Uint16(b[2:4]))
	fmt.Printf("ip.id 0x%04x\n", binary.BigEndian.Uint16(b[4:6]))
	v := binary.BigEndian.Uint16(b[6:8])
	var flags string
	switch {
	case v&0x4000 != 0 && v&0x2000 != 0:
		flags = "DF,MF"
	case v&0x4000 != 0:
		flags = "DF"
	case v&0x2000 != 0:
		flags = "MF"
	default:
		flags = "none"
	}
	fmt.Printf("ip.flags %s\n", flags)
	fmt.Printf("ip.frag_offset %d\n", int(v&0x1FFF)*8)

	fmt.Printf("ip.ttl %d\n", b[8])
	fmt.Printf("ip.protocol %d\n", b[9])
	fmt.Printf("ip.src %d.%d.%d.%d\n", b[12], b[13], b[14], b[15])
	fmt.Printf("ip.dst %d.%d.%d.%d\n", b[16], b[17], b[18], b[19])
	fmt.Printf("ip.checksum_valid %t\n", checksumValid(b, int(ihl)))
	totalLength := int(binary.BigEndian.Uint16(b[2:4]))
	switch b[9] {
	case 6:
		TCP(b[ihl:], totalLength, int(ihl))
	case 17:
		UDP(b[ihl:], totalLength, int(ihl))
	default:
		fmt.Printf("payload.length %d\n", totalLength-int(ihl))
	}
}

func checksumValid(b []byte, headerLen int) bool {
	var sum uint32
	for i := 0; i < headerLen; i += 2 {
		var word uint16
		if i == 10 {
			word = 0
		} else {
			word = binary.BigEndian.Uint16(b[i:i+2])
		}
		sum += uint32(word)
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	got := ^uint16(sum)
	want := binary.BigEndian.Uint16(b[10:12])
	return got == want
}

func TCP(b []byte, totalLength, ihlBytes int) {
	srcPort := binary.BigEndian.Uint16(b[0:2])
	dstPort := binary.BigEndian.Uint16(b[2:4])
	seq := binary.BigEndian.Uint32(b[4:8])
	ack := binary.BigEndian.Uint32(b[8:12])
	dataOffset := int(b[12]>>4) * 4
	flagsByte := b[13]
	window := binary.BigEndian.Uint16(b[14:16])

	fmt.Printf("tcp.src_port %d\n", srcPort)
	fmt.Printf("tcp.dst_port %d\n", dstPort)
	fmt.Printf("tcp.seq %d\n", seq)
	fmt.Printf("tcp.ack %d\n", ack)
	fmt.Printf("tcp.data_offset_bytes %d\n", dataOffset)
	fmt.Printf("tcp.flags %s\n", tcpFlags(flagsByte))
	fmt.Printf("tcp.window %d\n", window)

	fmt.Printf("payload.length %d\n", totalLength-ihlBytes-dataOffset)
}

func tcpFlags(b byte) string {
	var parts []string
	if b&0x01 != 0 {
		parts = append(parts, "FIN")
	}
	if b&0x02 != 0 {
		parts = append(parts, "SYN")
	}
	if b&0x04 != 0 {
		parts = append(parts, "RST")
	}
	if b&0x08 != 0 {
		parts = append(parts, "PSH")
	}
	if b&0x10 != 0 {
		parts = append(parts, "ACK")
	}
	if b&0x20 != 0 {
		parts = append(parts, "URG")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

func UDP(b []byte, totalLength, ihlBytes int) {
	srcPort := binary.BigEndian.Uint16(b[0:2])
	dstPort := binary.BigEndian.Uint16(b[2:4])
	length := binary.BigEndian.Uint16(b[4:6])

	fmt.Printf("udp.src_port %d\n", srcPort)
	fmt.Printf("udp.dst_port %d\n", dstPort)
	fmt.Printf("udp.length %d\n", length)

	fmt.Printf("payload.length %d\n", totalLength-ihlBytes-8)
}

func main() {
	Ethernet()
}