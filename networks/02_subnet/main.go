package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: subnet <CIDR>")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "subnet":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: subnet <CIDR>")
			os.Exit(1)
		}
		subnet(os.Args[2])
	case "route":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: route <file> <destination IP>")
			os.Exit(1)
		}
		route(os.Args[2], os.Args[3])
	default:
		fmt.Fprintln(os.Stderr, "Unknown command:", os.Args[1])
		os.Exit(1)
	}
}

func parseIP(s string) (uint32, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		fmt.Fprintln(os.Stderr, "Invalid IP address format")
		return 0, false
	}
	var ip uint32
	for _, part := range parts {
		num, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid IP address format")
			return 0, false
		}
		ip = (ip << 8) | uint32(num)
	}
	return ip, true
}

func ipString(ip uint32) string {
	first := (ip >> 24) & 0xFF
	second := (ip >> 16) & 0xFF
	third := (ip >> 8) & 0xFF
	fourth := ip & 0xFF
	return fmt.Sprintf("%d.%d.%d.%d", first, second, third, fourth)
}

func parseCIDR(s string) (ip uint32, prefix int, ok bool) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		fmt.Fprintln(os.Stderr, "Invalid CIDR format")
		return 0, 0, false
	}
	ip, ok = parseIP(parts[0])
	if !ok {
		fmt.Fprintln(os.Stderr, "Invalid IP address in CIDR")
		return 0, 0, false
	}
	val, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil || val < 0 || val > 32 {
		fmt.Fprintln(os.Stderr, "Invalid prefix in CIDR")
		return 0, 0, false
	}
	return ip, int(val), true
}

func mask(n int) uint32 {
	return uint32(0xFFFFFFFF) << (32 - n)
}

func subnet(s string) {
	ip, prefix, ok := parseCIDR(s)
	if !ok {
		os.Exit(1)
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
}

func route(file, dstArg string) {
	ip, ok := parseIP(dstArg)
	if !ok {
		os.Exit(1)
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
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		parts := strings.Fields(s)
		if len(parts) < 2 {
			fmt.Fprintln(os.Stderr, "Invalid route entry:", s)
			continue
		}
		cidr := parts[0]
		network, prefix, ok := parseCIDR(cidr)
		if !ok {
			fmt.Fprintln(os.Stderr, "Invalid CIDR in route entry:", cidr)
			continue
		}
		m := mask(prefix)
		if ip&m == network&m && prefix > bestPrefix {
			bestPrefix = prefix
			bestIface = parts[1]
		}
	}
	if bestPrefix == -1 {
		fmt.Println("unreachable true")
		os.Exit(1)
	} else {
		fmt.Printf("via %s\n", bestIface)
		fmt.Printf("prefix %d\n", bestPrefix)
	}
}
