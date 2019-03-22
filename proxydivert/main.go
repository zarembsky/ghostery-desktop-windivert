package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/ghostery/ghostery-desktop-windivert"
)

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8", // IPv4 loopback
		// Three following blocks of IP addresses are reserved by the
		// Internet Assigned Numbers Authority (IANA) for private Internets:
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func GenerateFilterString(exemptLocalhost bool) string {
	// We don't want to interrupt well-known, TCP based windows services that have nothing
	// to do with HTTP/HTTPS.
	// So, here we generate a WinDivert filter string that exempts such services.

	// This list of ports was taken from:
	// https://social.technet.microsoft.com/wiki/contents/articles/1772.windows-ports-protocols-and-system-services.aspx?Redirected=true#List_of_Ports
	exemptedPorts := []int{
		7,     // Echo
		9,     // Discard
		13,    // Daytime
		17,    // Quotd
		19,    // Chargen
		20,    // FTP
		21,    // FTP
		23,    // Telnet
		25,    // SMTP
		42,    // WINS
		53,    // DNS
		88,    // Kerberos
		102,   // X.400
		110,   // POP3
		119,   // NNTP
		135,   // RPC
		139,   // NetBIOS
		143,   // IMAP
		389,   // LDAP
		445,   // SMB
		464,   // Kerberos
		515,   // LPD
		548,   // File
		554,   // RTSP
		563,   // NNTP
		593,   // RPC
		636,   // LDAP
		993,   // IMAP
		995,   // POP3
		1067,  // Installation
		1068,  // Installation
		1270,  // MOM-Encrypted
		1433,  // SQL
		1723,  // PPTP
		1755,  // MMS
		1801,  // MSMQ
		2101,  // MSMQ-DCs
		2103,  // MSMQ-RPC
		2105,  // MSMQ-RPC
		2107,  // MSMQ-Mgmt
		2393,  // OLAP
		2394,  // OLAP
		2701,  // SMS
		2702,  // SMS
		2703,  // SMS
		2704,  // SMS
		2725,  // SQL
		2869,  // UPNP / SSDP
		3268,  // Global
		3269,  // Global
		3389,  // Terminal
		5000,  // SSDP
		5722,  // RPC
		6001,  // Information
		6002,  // Directory
		6004,  // DSProxy/NSPI
		42424, // ASP.Net
		51515, // MOM-Clear
	}

	var filterTail string
	for _, port := range exemptedPorts {
		filterTail += (" and tcp.DstPort != " + fmt.Sprint(port))
	}

	// var (
	// 	filterHTTP,
	// 	filterHTTPS
	//  ) string

	// switch exemptLocalhost {
	// case true:
	// 	{
	// 		filter = ("outbound and tcp and tcp.SrcPort == 8080 and tcp.DstPort == 80 and ((ip and ip.SrcAddr != 127.0.0.1) or (ipv6 and ipv6.SrcAddr != ::1))" + filter)
	// 	}
	// case false:
	// 	{
	// 		filterHTTP = "tcp and ip and outbound and !loopback and !impostor and (tcp.DstPort == 80 or tcp.SrcPort == 8080)" + filter
	// 		filterHTTPS := "tcp and ip and outbound and !loopback and !impostor and (tcp.DstPort == 443 or tcp.SrcPort == 4443)" + filter
	// 	}
	// }

	return filterTail
}
func DivertTraffic(proxyProcessId int, port uint16, proxyPort uint16, filterTail string, tcpHelper *godivert.TCPHelper, done chan string) {
	var v4ReturnPorts [65536]uint16
	var v4ShouldFilter [65536]uint16

	var v6ReturnPorts [65536]uint16
	var v6ShouldFilter [65536]uint16

	filter := fmt.Sprintf("tcp and (ip or ipv6) and outbound and !loopback and !impostor and (tcp.DstPort == %d or tcp.SrcPort == %d)", port, proxyPort) + filterTail
	//fmt.Println("FILTER", filter)
	winDivert, err := godivert.NewWinDivertHandle(filter, -1000, 0)
	defer winDivert.Close()
	if err != nil {
		done <- "\nFailed to open WinDivert handle. Are you running in non-admin mode?\n"
		return
	}

	gotProxyResponse := false
	proxyPid := int(0)
	if proxyProcessId > 0 {
		proxyPid = proxyProcessId
		gotProxyResponse = true
	}
	for {
		packet, err := winDivert.Recv()
		if err != nil {
			log.Printf("\nFailed to receive packet. Continue\n")
			continue
		}

		srcPort, err1 := packet.SrcPort()
		if err1 != nil {
			log.Printf("\nFailed to get source port for packet. Continue\n")
			packet.Send(winDivert)
			continue
		}

		srcIP := packet.SrcIP()
		ipVersion := packet.IpVersion()
		// if ipVersion == 6 {
		// 	fmt.Println("IP6 PACKET", packet)
		// }

		if packet.Syn() != false {
			packet.VerifyParsed()

			pid, err := tcpHelper.GetConnectionPID(int(srcPort), srcIP.String(), ipVersion)
			if err != nil {
				log.Printf("\nFailed to get process id for packet. Continue\n")
				packet.Send(winDivert)
				continue
			}

			if pid == -1 {
				fmt.Println("PACKET", ipVersion, packet)
				packet.Send(winDivert)
				continue
			}

			if gotProxyResponse == false && srcPort == proxyPort && pid != 0 && pid != os.Getpid() {
				proxyPid = pid
				gotProxyResponse = true
				log.Printf("\nFound proxy listening to port %d\n", proxyPort)
			}

			if pid == proxyPid {
				//fmt.Println("IT IS OUR PID DONT FILTER", ipVersion, srcPort)
				switch ipVersion {
				case 4:
					v4ShouldFilter[srcPort] = 0
				case 6:
					v6ShouldFilter[srcPort] = 0
				default:
				}
			} else {
				// if srcPort == proxyPort {
				// 	fmt.Println("FILTER", srcPort, pid)
				// }
				switch ipVersion {
				case 4:
					v4ShouldFilter[srcPort] = 1
				case 6:
					v6ShouldFilter[srcPort] = 1
				default:
				}
				processName, err := tcpHelper.GetProcessName(pid)
				if err != nil {
					fmt.Println(err)
				} else {
					fmt.Println(processName)
				}
			}
		}

		dstPort, err2 := packet.DstPort()
		if err2 != nil {
			log.Printf("\nFailed to get destination port for packet. Continue\n")
			packet.Send(winDivert)
			continue
		}
		dstIP := packet.DstIP()
		//fmt.Println("DESTINATION IP", dstIP, dstPort)
		//fmt.Println("IS PRIVATE IP?", isPrivateIP(dstIP))

		// if packet.Direction() == true {
		// 	//fmt.Println("INBOUND:************", srcPort, dstPort, srcIP, dstIP)
		// 	// if srcPort == HTTPPort {
		// 	// 	packet.SetSrcPort(ProxyPort)
		// 	// }
		// 	packet.Send(winDivert)
		// 	continue
		// }
		if packet.Direction() == false {
			if srcPort == proxyPort {
				switch ipVersion {
				case 4:
					//fmt.Printf("FROM PROXY SRC %s:%d DST %s:%d:%d\n", srcIP, srcPort, dstIP, dstPort, v4ReturnPorts[dstPort])
					packet.SetSrcPort(v4ReturnPorts[dstPort])
					packet.Addr.SetDirection(true)
					packet.SetDstIP(srcIP)
					packet.SetSrcIP(dstIP)
					//packet.CalcNewChecksum(winDivert)
				case 6:
					//fmt.Printf("FROM PROXY SRC %s:%d DST %s:%d:%d\n", srcIP, srcPort, dstIP, dstPort, v6ReturnPorts[dstPort])
					packet.SetSrcPort(v6ReturnPorts[dstPort])
					packet.Addr.SetDirection(true)
					packet.SetDstIP(srcIP)
					packet.SetSrcIP(dstIP)
					//packet.CalcNewChecksum(winDivert)
				default:
					// Do nothing
				}
				//fmt.Println("WIND DIVERT ADDRESS", packet.Addr)
			} else {
				switch ipVersion {
				case 4:
					if v4ShouldFilter[srcPort] > 0 {
						//fmt.Printf("NOT FROM PROXY SRC %s:%d DST %s:%d\n", srcIP, srcPort, dstIP, dstPort)
						v4ReturnPorts[srcPort] = dstPort
						packet.SetDstPort(proxyPort)
						packet.SetDstIP(srcIP)
						packet.SetSrcIP(dstIP)
						packet.Addr.SetDirection(true)
						//packet.CalcNewChecksum(winDivert)
					}
				case 6:
					if v6ShouldFilter[srcPort] > 0 {
						//fmt.Printf("NOT FROM PROXY SRC %s:%d DST %s:%d\n", srcIP, srcPort, dstIP, dstPort)
						v6ReturnPorts[srcPort] = dstPort
						packet.SetDstPort(proxyPort)
						packet.SetDstIP(srcIP)
						packet.SetSrcIP(dstIP)
						packet.Addr.SetDirection(true)
						//packet.CalcNewChecksum(winDivert)
					}
				default:
				}
			}
		}
		packet.Send(winDivert)
	}
}
func main() {
	var proxyProcessId int
	var proxyHttpPort = uint16(8080)
	var proxyHttpsPort = uint16(4443)
	var host string

	if len(os.Args) < 3 {
		fmt.Println("Not enough arguments. Launching WinDivert with default values")
		//	panic(errors.New("Not enough arguments to launch WinDivert"))
	} else {
		var err error
		proxyProcessId, err = strconv.Atoi(os.Args[1])
		if err != nil || proxyProcessId <= 0 {
			fmt.Println("Missing proxy process id")
		} else {
			fmt.Println("Proxy process id:", proxyProcessId)
		}

		path := os.Args[2]

		type Config struct {
			Port       uint16 `json:"port"`
			PortSecure uint16 `json:"port_secure"`
			Host       string `json:"host"`
		}
		config := Config{}

		_, err = toml.DecodeFile(path, config)
		if err != nil {
			fmt.Println("Unable to decode config file")
		} else {
			proxyHttpPort = config.Port
			proxyHttpsPort = config.PortSecure
			host = config.Host

			if proxyHttpPort == 0 || proxyHttpsPort == 0 || host == "" {
				fmt.Println("Incomplete config data")
			}
		}
	}

	const httpPort = uint16(80)
	const httpsPort = uint16(443)

	log.Println("Proxy Divert Started")
	tcpHelper, err := godivert.NewTCPHelper()
	if err != nil {
		panic(err)
	}

	defer tcpHelper.Close()

	udpDropFilter := "outbound and udp and (udp.DstPort == 80 || udp.DstPort == 443)"
	winDivertDropUDP, err2 := godivert.NewWinDivertHandle(udpDropFilter, -999, 2)
	defer winDivertDropUDP.Close()
	if err2 != nil {
		panic(err2)
	}
	filterTail := GenerateFilterString(false)

	doneHTTPS := make(chan string, 1)
	doneHTTP := make(chan string, 1)

	go DivertTraffic(proxyProcessId, httpsPort, proxyHttpsPort, filterTail, tcpHelper, doneHTTPS)
	go DivertTraffic(proxyProcessId, httpPort, proxyHttpPort, filterTail, tcpHelper, doneHTTP)

	log.Printf("\nHTTPS Routine exits with message \"%s\"", <-doneHTTPS)
	log.Printf("\nHTTP Routine exits with message \"%s\"", <-doneHTTP)
}
