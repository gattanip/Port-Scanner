import socket
import argparse
import nmap

def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"
                return port, "Open", service
            else:
                return port, "Closed", "-"
    except Exception as e:
        return port, "Error", str(e)

def scan_ports(host, port_range):
    print(f"Scanning {host} for open ports in range {port_range[0]}-{port_range[1]}...")
    results = []
    for port in range(port_range[0], port_range[1] + 1):
        result = scan_port(host, port)
        results.append(result)
        if result[1] == "Open":
            print(f"Port {result[0]}: {result[1]} ({result[2]})")
    return results

def save_results_to_file(results, file_name):
    with open(file_name, "w") as file:
        file.write("Port,Status,Service\n")
        for result in results:
            file.write(f"{result[0]},{result[1]},{result[2]}\n")
    print(f"Results saved to {file_name}")

def advanced_scan_with_nmap(host):
    try:
        nm = nmap.PortScanner()
        nm.scan(host, arguments="-sS")
        print(f"Nmap scan results for {host}:")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                state = nm[host][proto][port]["state"]
                name = nm[host][proto][port].get("name", "Unknown")
                print(f"Port {port}: {state} ({name})")
    except Exception as e:
        print(f"Error during Nmap scan: {e}")

def main():
    parser = argparse.ArgumentParser(description="Basic Port Scanner")
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-r", "--range", type=str, default="1-1024", help="Port range to scan (e.g., 1-1024)")
    parser.add_argument("-o", "--output", type=str, help="Save results to a file")
    parser.add_argument("--nmap", action="store_true", help="Perform advanced scan with nmap")
    args = parser.parse_args()

    host = args.host
    port_range = [int(p) for p in args.range.split("-")]

    if args.nmap:
        advanced_scan_with_nmap(host)
    else:
        results = scan_ports(host, port_range)
        if args.output:
            save_results_to_file(results, args.output)

if __name__ == "__main__":
    main()
