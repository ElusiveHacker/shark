#!/bin/bash

# Define the SERVICES array
# Format can be "service_name:port:protocol:plugins" or "port:protocol:plugins"
# Plugins are comma-separated if multiple are specified
SERVICES=(
    "23:TCP:telnet-ntlm-info"
    "22:TCP:ssh2-enum-algos"
    "21:TCP:ftp-anon"
    "123:UDP:ntp-info,ntp-monlist"
    "135:TCP:msrpc-enum"
    "137:UDP:nbstat"
    "389:TCP:ldap-rootdse"
    "http:80:TCP:http-headers"
    "443:TCP:ssl-enum-ciphers"
    "5985:TCP:http-headers"
    "1433:TCP:ms-sql-info,ms-sql-dac,ms-sql-ntlm-info"
    "2049:UDP:nfs-ls,nfs-showmount,nfs-statfs"
    "3306:TCP:mysql-empty-password,mysql-enum,mysql-variables"
    "5432:TCP:pgsql-brute"
    "1521:TCP:oracle-tns-version"
    "111:TCP:rpc-grind"
    "79:TCP:fingerprint-strings"
    "512:TCP:rexec-brute"
    "5900:TCP:vnc-brute,vnc-title,realvnc-auth-bypass"
    "161:UDP:snmp-sysdescr"
    "445:TCP:smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010,smb2-capabilities"
)

# Function to validate input as a single IP or CIDR
validate_input() {
    local input="$1"
    # Check if it's a single IP (e.g., 192.168.1.1)
    if [[ $input =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$input"
        for octet in "${octets[@]}"; do
            if (( octet < 0 || octet > 255 )); then
                return 1
            fi
        done
        return 0
    # Check if it's a CIDR (e.g., 192.168.1.0/24)
    elif [[ $input =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        local ip="${input%/*}"
        local mask="${input#*/}"
        if (( mask < 0 || mask > 32 )); then
            return 1
        fi
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if (( octet < 0 || octet > 255 )); then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Enum4linux function scanning for ADs and usernames.
enum4linux_function() {
    local host="$1"
    local port="$2"
    local proto="$3"
    local name="$4"
    if [ "$port" = "445" ] && [ "$proto" = "TCP" ]; then
        local tool="enum4linux-ng"
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool is not installed. Skipping enumeration for port $port."
        else
            echo "Running $tool $host"
            "$tool" "$host"
        fi
    fi
    # Add more conditions here for other ports/protocols as needed
}

# SMBMap function scanning for SMBshares.
smbmap_function() {
    local host="$1"
    local port="$2"
    local proto="$3"
    local name="$4"
    if [ "$port" = "445" ] && [ "$proto" = "TCP" ]; then
        local tool="smbmap"
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool is not installed. Skipping enumeration for port $port."
        else
            echo "Running $tool -H $host"
            "$tool" -H "$host"
        fi
    fi
    # Add more conditions here for other ports/protocols as needed
}

# snmpwalk function scanning for port 161..
snmpwalk_function() {
    local host="$1"
    local port="$2"
    local proto="$3"
    local name="$4"
    if [ "$port" = "161" ] && [ "$proto" = "UDP" ]; then
        local tool="snmpwalk"
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool is not installed. Skipping enumeration for port $port."
        else
            echo "Running $tool -v1 -c public $host"
            "$tool" -v1 -c public "$host"
        fi
    fi
    # Add more conditions here for other ports/protocols as needed
}

# smtp function scanning for port 25..
smtp_function() {
    local host="$1"
    local port="$2"
    local proto="$3"
    local name="$4"
    if [ "$port" = "25" ] && [ "$proto" = "TCP" ]; then
        local tool="smtp-user-enum"
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool is not installed. Skipping enumeration for port $port."
        else
            echo "Running $tool -M VRFY -U users.txt -t $host"
            "$tool"  -M VRFY -U users.txt -t "$host"
        fi
    fi
    # Add more conditions here for other ports/protocols as needed
}

# Template function to replicate.
template_function() {
    local host="$1"
    local port="$2"
    local proto="$3"
    local name="$4"
    if [ "$port" = "445" ] && [ "$proto" = "TCP" ]; then
        local tool="enum4linux"
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool is not installed. Skipping enumeration for port $port."
        else
            echo "Running $tool -a $host"
            "$tool" -a "$host"
        fi
    fi
    # Add more conditions here for other ports/protocols as needed
}

# Main script

# Prompt user for input
read -p "Enter IP or CIDR (192.168.1.1 or 192.168.1.0/24): " input

# Validate the input
if ! validate_input "$input"; then
    echo "Invalid IP or CIDR format."
    exit 1
fi

# Perform ping scan to identify live hosts
nmap -sn "$input" -oG - > live_hosts_ping_scan.txt

# Extract live and dead hosts from ping scan results
live_hosts=$(grep "Status: Up" live_hosts_ping_scan.txt | cut -d' ' -f2) 
dead_hosts=$(grep "Status: Down" live_hosts_ping_scan.txt | cut -d' ' -f2)

# Extract TCP and UDP ports from SERVICES array
declare -a tcp_ports
declare -a udp_ports
for service in "${SERVICES[@]}"; do
    parts=(${service//:/ })
    # Handle both 4-part and 3-part service formats
    if [ "${#parts[@]}" = 4 ]; then
        port="${parts[1]}"
        proto="${parts[2]}"
    elif [ "${#parts[@]}" = 3 ]; then
        port="${parts[0]}"
        proto="${parts[1]}"
    else
        echo "Invalid service format: $service" >&2
        continue
    fi
    if [ "$proto" = "TCP" ]; then
        tcp_ports+=("$port")
    elif [ "$proto" = "UDP" ]; then
        udp_ports+=("$port")
    fi
done

# Create comma-separated port lists for Nmap
tcp_ports_str=$(printf "%s," "${tcp_ports[@]}" | sed 's/,$//')
udp_ports_str=$(printf "%s," "${udp_ports[@]}" | sed 's/,$//')

# Initialize report file
report_file="report.txt"
> "$report_file"
echo "Scan Report for $input" >> "$report_file"
echo "Generated on: $(date)" >> "$report_file"
echo "----------------------------------------" >> "$report_file"

# Record dead hosts
echo "Dead Hosts:" >> "$report_file"
if [ -n "$dead_hosts" ]; then
    for dead_host in $dead_hosts; do
        echo "Host $dead_host is dead." >> "$report_file"
    done
else
    echo "No dead hosts detected." >> "$report_file"
fi
echo "----------------------------------------" >> "$report_file"

# Process live hosts
echo "Live Hosts:" >> "$report_file"
if [ -n "$live_hosts" ]; then
    for live_host in $live_hosts; do
        echo "Scanning host: $live_host..." >&2  # Progress message to stderr
        {
            echo "Host::::: $live_host:"
            # Scan TCP ports if any are specified
            if [ -n "$tcp_ports_str" ]; then
                nmap -sSV -Pn -n --min-rate=1000 -p "$tcp_ports_str" -oG - "$live_host" > tcp_scan.txt
                open_tcp_ports=$(grep "Ports:" tcp_scan.txt | grep -oP '\d+/open/tcp' | cut -d'/' -f1)
                for open_port in $open_tcp_ports; do
                    for service in "${SERVICES[@]}"; do
                        parts=(${service//:/ })
                        if [ "${#parts[@]}" = 4 ]; then
                            name="${parts[0]}"
                            port="${parts[1]}"
                            proto="${parts[2]}"
                            scripts="${parts[3]}"
                        elif [ "${#parts[@]}" = 3 ]; then
                            port="${parts[0]}"
                            proto="${parts[1]}"
                            scripts="${parts[2]}"
                            name="$proto on port $port"
                        else
                            continue
                        fi
                        if [ "$port" = "$open_port" ] && [ "$proto" = "TCP" ]; then
                            echo "- Port $port/$proto: open"
                            echo "  Service: $name"
                            if [ -n "$scripts" ]; then
                                echo "  Nmap Plugins Output ($scripts):"
                                nmap -p "$port" --script="$scripts" "$live_host" | sed 's/^/    /'
                            fi
                            echo "Additional TCP Tool Output:- "
                            enum4linux_function "$live_host" "$port" "$proto" "$name" | sed 's/^/    /'
                            smbmap_function "$live_host" "$port" "$proto" "$name" | sed 's/^/    /'
                            smtp_function "$live_host" "$port" "$proto" "$name" | sed 's/^/    /'
                        fi
                    done
                done
            fi
            # Scan UDP ports if any are specified
            if [ -n "$udp_ports_str" ]; then
                nmap -sUV -Pn -n --min-rate=1000 -p "$udp_ports_str" -oG - "$live_host" > udp_scan.txt
                open_udp_ports=$(grep "Ports:" udp_scan.txt | grep -oP '\d+/open/udp' | cut -d'/' -f1)
                for open_port in $open_udp_ports; do
                    for service in "${SERVICES[@]}"; do
                        parts=(${service//:/ })
                        if [ "${#parts[@]}" = 4 ]; then
                            name="${parts[0]}"
                            port="${parts[1]}"
                            proto="${parts[2]}"
                            scripts="${parts[3]}"
                        elif [ "${#parts[@]}" = 3 ]; then
                            port="${parts[0]}"
                            proto="${parts[1]}"
                            scripts="${parts[2]}"
                            name="$proto on port $port"
                        else
                            continue
                        fi
                        if [ "$port" = "$open_port" ] && [ "$proto" = "UDP" ]; then
                            echo "- Port $port/$proto: open"
                            echo "  Service: $name"
                            if [ -n "$scripts" ]; then
                                echo "  Nmap Plugins Output ($scripts):"
                                nmap -p "$port" --script="$scripts" "$live_host" | sed 's/^/    /'
                            fi
                            echo "Additional UDP Tool Output:- "
                            snmpwalk_function "$live_host" "$port" "$proto" "$name" | sed 's/^/    /'
                        fi
                    done
                done
            fi
            echo "----------------------------------------"
        } >> "$report_file"
    done
else
    echo "No live hosts detected." >> "$report_file"
    echo "----------------------------------------" >> "$report_file"
fi

echo "Scan completed. Results saved to $report_file"
