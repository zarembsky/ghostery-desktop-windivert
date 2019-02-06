package main

import (
	"fmt"
	"log"
	"net"

	"godivert"
)

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
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

func DivertTraffic(port uint16, proxyPort uint16, filterTail string, tcpHelper *godivert.TCPHelper, done chan string) {
	var portsArray [65536]uint16
	var v4ShouldFilter [65536]uint16

	filter := fmt.Sprintf("tcp and ip and outbound and !loopback and !impostor and (tcp.DstPort == %d or tcp.SrcPort == %d)", port, proxyPort) + filterTail;
	fmt.Println("FILTER", filter)
	winDivert, err := godivert.NewWinDivertHandle(filter, -1000, 0)
	defer winDivert.Close()
	if err != nil {
		done <- "Failed to open WinDivert handle. Are you running in non-admin mode?"
		return
	}
	gotProxyResponse := false;
	proxyPid := int(0)
	for {
		packet, err := winDivert.Recv()
		if err != nil {
			log.Printf("Failed to receive packet. Continue")
			continue
		}

		srcPort, err1 := packet.SrcPort()
		if err1 != nil {
			log.Printf("Failed to get source port for packet. Continue")
			packet.Send(winDivert)
			continue
		}

		srcIP := packet.SrcIP()
		if packet.Syn() != false {
			packet.VerifyParsed()
			ipVersion := packet.IpVersion()

			pid, err := tcpHelper.GetConnectionPID(int(srcPort), srcIP.String(), ipVersion)
			if err != nil {
				log.Printf("Failed to get process id for packet. Continue")
				packet.Send(winDivert)
				continue
			}

			if gotProxyResponse == false && srcPort == proxyPort && pid != 0 {
				proxyPid = pid
				gotProxyResponse = true
			}

			if pid == proxyPid /*os.Getpid()*/ {
				v4ShouldFilter[srcPort] = 0
				//fmt.Println("IT IS OUR PID DONT FILTER", srcPort)
			} else {
				// if srcPort == proxyPort {
				// 	fmt.Println("FILTER", srcPort, pid)
				// }
				v4ShouldFilter[srcPort] = 1
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
			log.Printf("Failed to get destination port for packet. Continue")
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
			if srcPort == proxyPort  {
				//fmt.Printf("FROM PROXY SRC %s:%d DST %s:%d:%d\n", srcIP, srcPort, dstIP, dstPort, PortsArray[dstPort])
				packet.SetSrcPort(portsArray[dstPort])
				packet.Addr.SetDirection(true)
				packet.SetDstIP(srcIP)
				packet.SetSrcIP(dstIP)
//				packet.CalcNewChecksum(winDivert)
				//fmt.Println("WIND DIVERT ADDRESS", packet.Addr)
			} else {
				//fmt.Printf("NOT FROM PROXY SRC %s:%d DST %s:%d\n", srcIP, srcPort, dstIP, dstPort)
				//portsArray[srcPort] = dstPort
				// Reflect: PORT ---> PROXY
				if v4ShouldFilter[srcPort] > 0 {
					//fmt.Printf("NOT FROM PROXY REFLECTED SRC %s:%d DST %s:%d\n", srcIP, srcPort, dstIP, dstPort)
					portsArray[srcPort] = dstPort
					packet.SetDstPort(proxyPort)
					packet.SetDstIP(srcIP)
					packet.SetSrcIP(dstIP)
					packet.Addr.SetDirection(true)
//					packet.CalcNewChecksum(winDivert)
				}
			}
		}
		packet.Send(winDivert)
	}
}
func main() {
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

	go DivertTraffic(443, 4443, filterTail, tcpHelper, doneHTTPS)
	go DivertTraffic(80, 8080, filterTail, tcpHelper, doneHTTP)

	log.Printf("\nHTTPS Routine exits with message \"%s\"", <-doneHTTPS)
	log.Printf("\nHTTP Routine exits with message \"%s\"", <-doneHTTP)
}
