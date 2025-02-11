package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const banner = `
  █████████ █████  ███████████████ ███████████    ███████      ███████   ███████████
 ███░░░░░██░░███  ░░██░███░░░░░██░███░░░░░███ ███░░░░░███  ███░░░░░███░█░░░███░░░█
░███    ░░░ ░███   ░███░███    ░███░███    ░██████     ░░██████     ░░██░   ░███  ░ 
░░█████████ ░███   ░███░██████████ ░██████████░███      ░██░███      ░███   ░███    
 ░░░░░░░░███░███   ░███░███░░░░░███░███░░░░░██░███      ░██░███      ░███   ░███    
 ███    ░███░███   ░███░███    ░███░███    ░██░░███     ███░░███     ███    ░███    
░░█████████ ░░████████ ███████████ █████   ████░░░███████░  ░░░███████░     █████   
 ░░░░░░░░░   ░░░░░░░░ ░░░░░░░░░░░ ░░░░░   ░░░░░  ░░░░░░░      ░░░░░░░      ░░░░░    
                   SUBROOT by MikiVirus - Fast Subdomain Scanner
`

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
)

func main() {
	domain := flag.String("d", "", "Target domain (e.g., example.com)")
	wordlist := flag.String("w", "", "Path to wordlist file")
	output := flag.String("o", "", "Output file to save results")
	workers := flag.Int("t", 100, "Number of concurrent threads")
	resolver := flag.String("r", "8.8.8.8", "DNS resolver to use")
	flag.Parse()

	if *domain == "" || *wordlist == "" {
		fmt.Printf("%s[-] Usage: ./subroot -d <domain> -w <wordlist> [-o <output>] [-t <threads>] [-r <resolver>]\n%s", ColorRed, ColorReset)
		os.Exit(1)
	}

	fmt.Println(ColorCyan + banner + ColorReset)
	fmt.Printf("%s[+] Scanning domain: %s%s\n", ColorYellow, *domain, ColorReset)
	fmt.Printf("%s[+] Using wordlist: %s%s\n", ColorYellow, *wordlist, ColorReset)
	fmt.Printf("%s[+] Threads: %d%s\n", ColorYellow, *workers, ColorReset)
	fmt.Printf("%s[+] DNS Resolver: %s%s\n", ColorYellow, *resolver, ColorReset)

	fmt.Printf("\n%s[+] Progress: 0/%d%s", ColorYellow, 0, ColorReset)

	subs, total, err := loadWordlist(*wordlist)
	if err != nil {
		fmt.Printf("%s[-] Error loading wordlist: %s%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}

	results := make(chan string, *workers)
	progress := make(chan int, *workers) // Channel to track progress
	var wg sync.WaitGroup

	go displayProgress(progress, total)

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range subs {
				progress <- 1 // Increment progress
				subdomain := fmt.Sprintf("%s.%s", sub, *domain)
				if isAliveDNS(subdomain, *resolver) || isAliveHTTP(subdomain) || isAlivePing(subdomain) {
					results <- subdomain
				}
			}
		}()
	}

	go func() {
		for result := range results {
			fmt.Printf("\n%s[+] Subdomain found: %s%s\n", ColorGreen, result, ColorReset)
		}
	}()

	go func() {
		wg.Wait()
		close(results)
		close(progress)
	}()

	var outputFile *os.File
	if *output != "" {
		outputFile, err = os.Create(*output)
		if err != nil {
			fmt.Printf("%s[-] Error creating output file: %s%s\n", ColorRed, err, ColorReset)
			os.Exit(1)
		}
		defer outputFile.Close()
	}

	for result := range results {
		if outputFile != nil {
			outputFile.WriteString(result + "\n")
		}
	}

	fmt.Println(ColorGreen + "\n[+] Scan completed." + ColorReset)
}

func displayProgress(progress chan int, total int) {
	count := 0
	for range progress {
		count++
		fmt.Printf("\033[1F\033[2K%s[+] Progress: %d/%d%s", ColorYellow, count, total, ColorReset)
	}
}

func loadWordlist(path string) (chan string, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}

	var total int
	lines := []string{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	file.Close()

	subs := make(chan string, len(lines))

	go func() {
		defer close(subs)
		for _, line := range lines {
			subs <- line
		}
	}()

	total = len(lines)
	return subs, total, nil
}

func isAliveDNS(subdomain, resolver string) bool {
	client := &dns.Client{
		Timeout: 5 * time.Second,
	}
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(subdomain), dns.TypeANY)

	for i := 0; i < 3; i++ {
		response, _, err := client.Exchange(msg, net.JoinHostPort(resolver, "53"))
		if err == nil {
			for range response.Answer {
				return true
			}
		}
	}
	return false
}

func isAliveHTTP(subdomain string) bool {
	url := fmt.Sprintf("http://%s", subdomain)
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	resp, err := client.Get(url)
	if err == nil && resp.StatusCode < 500 {
		return true
	}
	return false
}

func isAlivePing(subdomain string) bool {
	cmd := exec.Command("ping", "-c", "1", subdomain)
	err := cmd.Run()
	return err == nil
}
