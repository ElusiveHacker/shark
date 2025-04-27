#!/bin/bash

# Define the SERVICES array
# Format: "service_name:port:protocol:plugins" or "port:protocol:plugins"
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
    "445:TCP:smb-enum-shares,smb-enum-users"
    "88:TCP:fingerprint-strings"
)

# Function to validate input as a single IP or CIDR
validate_input() {
    local input="$1"
    if [[ $input =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$input"
        for octet in "${octets[@]}"; do
            if (( octet < 0 || octet > 255 )); then
                return 1
            fi
        done
        return 0
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

# Function to strip ANSI escape codes
strip_ansi() {
    sed 's/\x1B\[[0-9;]*[JKmsu]//g'
}

# Enum4linux-ng function for AD enumeration
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
            echo "Running $tool -a $host"
            "$tool" -a "$host" 2>> "$OUTPUT_DIR/error.log" | strip_ansi
        fi
    fi
}

# SMBMap function for SMB share enumeration
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
            "$tool" -H "$host" 2>> "$OUTPUT_DIR/error.log" | strip_ansi
        fi
    fi
}

# SNMPwalk function for SNMP enumeration
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
            "$tool" -v1 -c public "$host" 2>> "$OUTPUT_DIR/error.log" | strip_ansi
        fi
    fi
}

# SMTP function for SMTP user enumeration
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
            "$tool" -M VRFY -U users.txt -t "$host" 2>> "$OUTPUT_DIR/error.log" | strip_ansi
        fi
    fi
}

# Kerberoasting function for AD service account enumeration
kerberoast_function() {
    local host="$1"
    local port="$2"
    local proto="$3"
    local name="$4"
    if { [ "$port" = "88" ] || [ "$port" = "389" ]; } && [ "$proto" = "TCP" ]; then
        local tool="GetUserSPNs.py"
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool is not installed. Skipping Kerberoasting for port $port."
        else
            read -p "Enter AD username (e.g., user@domain.com): " ad_user
            read -sp "Enter AD password: " ad_pass
            echo
            echo "Running $tool for $ad_user on $host"
            "$tool" -dc-ip "$host" -request "$ad_user:$ad_pass" -outputfile "$OUTPUT_DIR/kerberoast_$host.txt" 2>> "$OUTPUT_DIR/error.log" | strip_ansi
            if [ -s "$OUTPUT_DIR/kerberoast_$host.txt" ]; then
                echo "Kerberoasting output saved to $OUTPUT_DIR/kerberoast_$host.txt"
            else
                echo "No SPNs found or Kerberoasting failed."
            fi
        fi
    fi
}

# Main script
read -p "Enter IP or CIDR (192.168.1.1 or 192.168.1.0/24): " input
OUTPUT_DIR="scan_output_$(date +%F_%H-%M-%S)"
mkdir -p "$OUTPUT_DIR"

if ! validate_input "$input"; then
    echo "Invalid IP or CIDR format."
    exit 1
fi

nmap -sn "$input" -oG - > "$OUTPUT_DIR/live_hosts_ping_scan.txt"
live_hosts=$(grep "Status: Up" "$OUTPUT_DIR/live_hosts_ping_scan.txt" | cut -d' ' -f2)
dead_hosts=$(grep "Status: Down" "$OUTPUT_DIR/live_hosts_ping_scan.txt" | cut -d' ' -f2)

declare -a tcp_ports
declare -a udp_ports
for service in "${SERVICES[@]}"; do
    parts=(${service//:/ })
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

tcp_ports_str=$(printf "%s," "${tcp_ports[@]}" | sed 's/,$//')
udp_ports_str=$(printf "%s," "${udp_ports[@]}" | sed 's/,$//')

report_file="$OUTPUT_DIR/report.txt"
> "$report_file"
echo "Scan Report for $input" >> "$report_file"
echo "Generated on: $(date)" >> "$report_file"
echo "----------------------------------------" >> "$report_file"

echo "Dead Hosts:" >> "$report_file"
if [ -n "$dead_hosts" ]; then
    for dead_host in $dead_hosts; do
        echo "Host $dead_host is dead." >> "$report_file"
    done
else
    echo "No dead hosts detected." >> "$report_file"
fi
echo "----------------------------------------" >> "$report_file"

echo "Live Hosts:" >> "$report_file"
if [ -n "$live_hosts" ]; then
    for live_host in $live_hosts; do
        echo "Scanning host: $live_host..." >&2
        {
            echo "Host: $live_host"
            if [ -n "$tcp_ports_str" ]; then
                nmap -sSV -Pn -n --min-rate=1000 -p "$tcp_ports_str" -oG - "$live_host" > "$OUTPUT_DIR/tcp_scan_$live_host.txt"
                open_tcp_ports=$(grep "Ports:" "$OUTPUT_DIR/tcp_scan_$live_host.txt" | grep -oP '\d+/open/tcp' | cut -d'/' -f1)
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
                                nmap -p "$port" --script="$scripts" "$live_host" | strip_ansi | sed 's/^/    /'
                            fi
                            echo "  Additional TCP Tool Output:"
                            case "$port" in
                                "445")
                                    enum4linux_function "$live_host" "$port" "$proto" "$name" | sed 's/^/    /'
                                    smbmap_function "$live_host" "$port" "$proto" "$name" | sed 's/^/    /'
                                    ;;
                                "88"|"389")
                                    kerberoast_function "$live_host" "$port" "$proto" "$name" | sed 's/^/    /'
                                    ;;
                                "25")
                                    smtp_function "$live_host" "$port" "$proto" "$name" | sed 's/^/    /'
                                    ;;
                            esac
                        fi
                    done
                done
            fi
            if [ -n "$udp_ports_str" ]; then
                nmap -sUV -Pn -n --min-rate=1000 -p "$udp_ports_str" -oG - "$live_host" > "$OUTPUT_DIR/udp_scan_$live_host.txt"
                open_udp_ports=$(grep "Ports:" "$OUTPUT_DIR/udp_scan_$live_host.txt" | grep -oP '\d+/open/udp' | cut -d'/' -f1)
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
                                nmap -p "$port" --script="$scripts" "$live_host" | strip_ansi | sed 's/^/    /'
                            fi
                            echo "  Additional UDP Tool Output:"
                            case "$port" in
                                "161")
                                    snmpwalk_function "$live_host" "$port" "$proto" "$name" | sed 's/^/    /'
                                    ;;
                            esac
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
