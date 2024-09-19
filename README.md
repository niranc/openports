# OpenPorts

OpenPorts is a Bash script for analyzing and displaying open ports on Linux systems. It uses `ss`, `netstat`, and Docker (if available) to gather comprehensive information about network connections and exposed ports.

⚠️ **SECURITY WARNING** ⚠️
This script requires root privileges to function properly. Always review scripts carefully before running them with elevated permissions. Use at your own risk.

## Usage

1. Make the script executable:
   ```
   chmod +x openports.sh
   ```

2. Run with sudo:
   ```
   sudo ./openports.sh
   ```

## Example Results
Here's an example of the output you might see when running OpenPorts:

### Ports ouverts IPv4 sur 127.0.0.1 (Loopback)

| PORT | PROTOCOL | COMMAND   | IP        |
|------|----------|-----------|-----------|
| 53   | udp      | service-a | 127.0.0.1 |
| 631  | tcp      | service-b | 127.0.0.1 |
| 5432 | tcp      | service-c | 127.0.0.1 |
| 27017| tcp      | service-d | 127.0.0.1 |

### Ports ouverts IPv4 sur 0.0.0.0 (Externe)

| PORT | PROTOCOL | COMMAND   | IP      |
|------|----------|-----------|---------|
| 111  | udp      | service-e | 0.0.0.0 |
| 631  | udp      | service-f | 0.0.0.0 |
| 2049 | udp      | -         | 0.0.0.0 |
| 5353 | udp      | service-g | 0.0.0.0 |
| 8443 | tcp      | service-h | 0.0.0.0 |

### Ports ouverts IPv6 sur ::1 (Loopback)

| PORT | PROTOCOL | COMMAND   | IP   |
|------|----------|-----------|------|
| 631  | tcp6     | service-i | ::1  |

### Ports ouverts IPv6 sur [::] (Externe)

| PORT | PROTOCOL | COMMAND   | IP   |
|------|----------|-----------|------|
| 80   | tcp6     | service-j | [::] |
| 111  | udp6     | service-k | [::] |
| 631  | tcp6     | service-l | [::] |
| 2049 | udp6     | -         | [::] |
| 5353 | udp6     | service-m | [::] |
| 8443 | tcp      | service-n | [::] |

