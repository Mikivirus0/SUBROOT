# Subroot - Fast Subdomain Scanner

Subroot is a high-performance subdomain scanner designed for security researchers and penetration testers. It leverages DNS resolution, HTTP requests, and ICMP pings to identify active subdomains efficiently.

## Features
- Fast subdomain enumeration using concurrent workers
- DNS resolution checks with a custom resolver
- HTTP request validation for live subdomains
- ICMP ping detection for additional verification
- Progress tracking for better visibility
- Supports custom wordlists
- Output results to a file

## Installation
### Clone the Repository
```sh
git clone https://github.com/MikiVirus/subroot.git
cd subroot
```

### Build the Binary
Ensure you have Go installed on your system.
```sh
go build -o subroot
```

## Usage
```sh
./subroot -d <domain> -w <wordlist> [-o <output>] [-t <threads>] [-r <resolver>]
```

### Options
| Flag        | Description                                      |
|------------|--------------------------------------------------|
| `-d`       | Target domain (e.g., example.com)               |
| `-w`       | Path to the wordlist file                        |
| `-o`       | Output file to save results (optional)           |
| `-t`       | Number of concurrent threads (default: 100)     |
| `-r`       | Custom DNS resolver (default: 8.8.8.8)          |

### Example
```sh
./subroot -d example.com -w subdomains.txt -o results.txt -t 200 -r 1.1.1.1
```

## Dependencies
- `github.com/miekg/dns`

Install dependencies using:
```sh
go mod tidy
```

## How It Works
1. Loads subdomains from a wordlist.
2. Performs DNS resolution using the specified resolver.
3. Checks HTTP response status for live subdomains.
4. Uses ICMP pings to verify subdomain activity.
5. Displays progress and saves results.

## Disclaimer
Subroot is intended for educational and security testing purposes only. Use it responsibly and ensure you have permission before scanning any domains.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author
Developed by **MikiVirus**.

## Contributions
Contributions are welcome! Feel free to submit issues and pull requests.

---
Happy hunting! 🛡️