# WireGuard Namespace Manager

A powerful bash script to manage multiple isolated WireGuard tunnels and Xray proxy instances using Linux network namespaces.

## Features

- 🔒 **Isolated Network Namespaces**: Each WireGuard tunnel runs in its own isolated namespace
- 🚀 **Automatic Xray Setup**: Automatically configures Xray proxy with VLESS protocol
- 🎭 **HTTP Header Obfuscation**: Built-in support for HTTP header obfuscation
- 🔧 **Auto Dependency Installation**: Automatically installs required dependencies
- 📊 **Status Monitoring**: Real-time status monitoring of all tunnels
- 🐛 **Debug Tools**: Built-in debugging and troubleshooting tools
- 🔄 **Port Forwarding**: Automatic NAT and port forwarding configuration

## Requirements

- Linux operating system
- Root privileges
- Linux kernel with WireGuard support
- Network namespace support (usually available by default)

## Installation

1. Clone or download the script:
```bash
wget https://raw.githubusercontent.com/alihm-us/wireguard-namespace-manager/main/setup-wg.sh
chmod +x setup-wg.sh
```

2. Make the script executable and run it:
```bash
sudo ./setup-wg.sh
```

## Usage

### Creating a New Setup

1. Run the script: `sudo ./setup-wg.sh`
2. Select option `1` (Create New Setup)
3. Enter the path to your WireGuard config file
4. Enter the port number you want to use (this will be the public VLESS port)
5. **In your V2Ray/Xray panel**, first create an **inbound** for this server with your desired settings (UUID, transport, headers, etc.), then copy its **VLESS URI** (for example: `vless://...`).
6. When the script finishes the WireGuard setup, it will ask for a **VLESS URI**. Paste the URI from your panel so the inbound inside the namespace matches the panel config exactly.
7. The script will automatically:
   - Create an isolated network namespace
   - Set up the WireGuard tunnel
   - Configure routing and NAT
   - Start an Xray proxy inside the namespace using the imported VLESS config (or a simple default one if you skip the URI)
   - Display a ready-to-use connection string

### Managing Xray

Select option `2` to manage Xray instances for an existing port:

- **Start/Restart Xray**
  - Enter the port number (for example `49021`)
  - Optionally paste a full VLESS URI to import:
    - If you paste a URI, the script parses:
      - UUID
      - `type` (must be `tcp`)
      - `security` (e.g. `none`)
      - `headerType=http`, `host`, `path` (if present)
    - And generates an inbound that matches your panel config.
  - If you skip the URI, it will ask for:
    - UUID (with a default value)
    - Optional HTTP header (Host + Path)
- **Stop Xray**
- **View logs** (`/tmp/xray-{PORT}.log`)

### Restarting WireGuard

Select option `3` to restart the WireGuard tunnel for a given port:

- Brings the WireGuard interface **down** and then **up** inside the namespace
- Re-applies minimal routing (default route via WireGuard + endpoint route)
- Waits for a new handshake and shows the latest handshake time

### Deleting a Setup

Select option `4` to delete a setup:
- Deletes the namespace
- Deletes the veth pair
- Cleans up all related `iptables` rules (DNAT/FORWARD/LOG)

### Debugging

Select option `5` to debug a setup:
- Collects comprehensive debug information
- Saves to `/tmp/debug-{PORT}.log`
- Optional real-time packet logging


## Connection String Formats

Depending on your inbound configuration, the script can generate two main VLESS forms:

- **Simple TCP VLESS (no HTTP header)**:

  ```text
  vless://{UUID}@{SERVER_IP}:{PORT}?type=tcp&encryption=none&security=none
  ```

- **TCP VLESS with HTTP header (obfuscation)**:

  ```text
  vless://{UUID}@{SERVER_IP}:{PORT}?encryption=none&type=tcp&headerType=http&host={HOST}&path={PATH}&security=none
  ```

## Network Architecture

Each setup creates:
- A network namespace (`ns-{PORT}`)
- A veth pair for host-namespace communication
- A WireGuard interface inside the namespace
- Xray proxy listening on the specified port
- iptables rules for port forwarding and NAT
- Per-namespace DNS configuration (`/etc/netns/ns-{NAME}/resolv.conf`)

## Troubleshooting

### WireGuard not working
- Check if WireGuard module is loaded: `lsmod | grep wireguard`
- Verify your WireGuard config file is valid
- Check namespace routing: `ip netns exec ns-{PORT} ip route`

### Xray not starting
- Check logs: `/tmp/xray-{PORT}.log`
- Verify port is not in use: `ss -ltn | grep {PORT}`
- Ensure Xray binary is installed: `/usr/local/bin/xray-ns`

### Port forwarding issues
- Check iptables rules: `iptables -t nat -L PREROUTING -n -v`
- Verify FORWARD rules: `iptables -L FORWARD -n -v`
- Ensure IP forwarding is enabled: `sysctl net.ipv4.ip_forward`

## Files Created

- `/tmp/xray-{PORT}.json` - Xray configuration file
- `/tmp/xray-{PORT}.log` - Xray log file
- `/tmp/debug-{PORT}.log` - Debug information (when using debug option)
- `/etc/netns/ns-{PORT}/resolv.conf` - DNS configuration for namespace

## Security Notes

- This script requires root privileges
- WireGuard config files may contain sensitive information
- Xray configs are stored in `/tmp` (cleared on reboot)
- Ensure proper firewall rules are in place

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions, please open an issue on GitHub.

## Changelog

### Version 1.0.0
- Initial release
- Basic WireGuard namespace management
- Automatic Xray setup
- HTTP header obfuscation support
- Debug tools

