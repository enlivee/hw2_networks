package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func usage() {
	prog := os.Args[0]
	fmt.Fprintf(os.Stderr, "Usage:\n  %s subnet <CIDR>\n  %s route <file> <destination IP>\n", prog, prog)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "subnet":
		if len(os.Args) < 3 {
			usage()
			os.Exit(1)
		}
		if err := subnet(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "route":
		if len(os.Args) < 4 {
			usage()
			os.Exit(1)
		}
		os.Exit(route(os.Args[2], os.Args[3]))
	default:
		fmt.Fprintln(os.Stderr, "Unknown command:", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func parseIP(s string) (uint32, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("invalid ip %q", s)
	}
	var ip uint32
	for _, part := range parts {
		num, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return 0, fmt.Errorf("invalid ip %q", s)
		}
		ip = (ip << 8) | uint32(num)
	}
	return ip, nil
}

func ipString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}

func parseCIDR(s string) (uint32, int, error) {
	addr, prefixStr, found := strings.Cut(s, "/")
	if !found {
		return 0, 0, fmt.Errorf("invalid cidr %q: no prefix", s)
	}
	ip, err := parseIP(addr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid cidr %q: %w", s, err)
	}
	val, err := strconv.ParseUint(prefixStr, 10, 8)
	if err != nil || val > 32 {
		return 0, 0, fmt.Errorf("invalid cidr %q: bad prefix", s)
	}
	return ip, int(val), nil
}

func mask(n int) uint32 {
	return uint32(0xFFFFFFFF) << (32 - n)
}

func subnet(s string) error {
	ip, prefix, err := parseCIDR(s)
	if err != nil {
		return err
	}
	netmask := mask(prefix)
	network := ip & netmask
	broadcast := network | ^netmask
	size := uint64(1) << (32 - prefix)

	var first, last uint32
	var hosts uint64
	bcast := ipString(broadcast)
	switch prefix {
	case 32:
		first = network
		last = network
		hosts = 1
		bcast = "none"
	case 31:
		first = network
		last = network + 1
		hosts = 2
		bcast = "none"
	default:
		first = network + 1
		last = broadcast - 1
		hosts = size - 2
	}
	fmt.Printf("network %s\n", ipString(network))
	fmt.Printf("broadcast %s\n", bcast)
	fmt.Printf("netmask %s\n", ipString(netmask))
	fmt.Printf("prefix %d\n", prefix)
	fmt.Printf("first %s\n", ipString(first))
	fmt.Printf("last %s\n", ipString(last))
	fmt.Printf("hosts %d\n", hosts)
	return nil
}

func route(file, dstArg string) int {
	ip, err := parseIP(dstArg)
	if err != nil{
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	f, err := os.Open(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening file:", err)
		os.Exit(1)
	}
	defer f.Close()

	bestPrefix := -1
	bestIface := ""

	scanner := bufio.NewScanner(f)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		s := strings.TrimSpace(scanner.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		parts := strings.Fields(s)
		if len(parts) < 2 {
			fmt.Fprintf(os.Stderr, "line %d: invalid route entry %q\n", lineNo, s)
			continue
		}
		network, prefix, err := parseCIDR(parts[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "line %d: %v\n", lineNo, err)
			continue
		}
		m := mask(prefix)
		if ip&m == network&m && prefix > bestPrefix {
			bestPrefix = prefix
			bestIface = parts[1]
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error reading file:", err)
		return 1
	}
	if bestPrefix == -1 {
		fmt.Println("unreachable true")
		return 1
	}
	fmt.Printf("via %s\n", bestIface)
	fmt.Printf("prefix %d\n", bestPrefix)
	return 0
}
