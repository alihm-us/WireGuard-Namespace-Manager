# WireGuard Namespace Manager

A powerful Python tool for managing multiple isolated WireGuard tunnels and Xray proxy instances using Linux network namespaces. Each tunnel runs in its own namespace with automatic Xray setup, UUID management, and auto-restore capabilities.

## Features

- **Multiple Isolated Tunnels**: Create and manage multiple WireGuard tunnels, each running in its own Linux network namespace
- **Automatic Xray Integration**: Automatically configure and manage Xray proxy instances for each tunnel
- **Panel Integration**: Supports x-ui and Marzban panels with automatic UUID extraction from database
- **Auto UUID Refresh**: Background watcher automatically updates UUIDs from panel database every 5 seconds (configurable)
- **Auto-Restore After Reboot**: Automatically restores all tunnels after server reboot via systemd service
- **Smart Resource Management**: Only restarts Xray when UUIDs actually change, preventing unnecessary resource usage
- **Interactive Setup Wizard**: First-time setup wizard for easy configuration
- **Comprehensive Status Display**: Real-time status of tunnels, Xray processes, and UUID counts
- **Debug Tools**: Built-in debugging and troubleshooting tools

## Requirements

- Linux system with root access
- Python 3.6+
- WireGuard kernel module
- Required packages: `wireguard-tools`, `iproute2`, `iptables`, `curl`
- Xray binary (automatically downloaded if not present)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/alihm-us/WireGuard-Namespace-Manager.git
cd WireGuard-Namespace-Manager
```

2. Make the script executable:
```bash
chmod +x WGNM.py
```

3. Run the script (it will check and install dependencies automatically):
```bash
sudo python3 WGNM.py
```

## First-Time Setup

On first run, the script will launch an interactive setup wizard that guides you through:

1. **Panel Selection**: Choose your panel (x-ui, Marzban, or None)
2. **Database Path**: Configure the path to your panel's database file
3. **UUID Refresh Interval**: Set how often to check for new UUIDs (default: 5 seconds)
4. **Auto-Restore**: Enable automatic tunnel restoration after reboot

The configuration is saved to `/root/.config/wgnm/config.json` and can be modified later.

## Usage

### Main Menu

When you run the script, you'll see the main menu with the following options:

1. **Create New Setup**: Create a new WireGuard tunnel with Xray proxy
2. **Manage Xray**: Start, stop, or restart Xray processes for tunnels
3. **Restart WireGuard**: Restart WireGuard interfaces
4. **Delete Setup**: Remove a tunnel and its namespace
5. **Debug Setup**: Debug and troubleshoot tunnel issues
6. **Restore All Tunnels**: Manually restore all tunnels (useful after reboot)
7. **Restore Tunnel from Config File**: Restore a tunnel from a WireGuard config file
8. **Setup Auto-Restore**: Configure systemd service for automatic restoration
9. **Exit**: Exit the script

### Command-Line Options

The script supports several command-line options:

```bash
# Run in interactive mode (default)
sudo python3 WGNM.py

# Run in auto-refresh mode (background, no menu)
sudo python3 WGNM.py --auto-refresh
# or
sudo python3 WGNM.py --watch

# Restore all tunnels (used by systemd service)
sudo python3 WGNM.py --restore
```

### Creating a Tunnel

1. Select option `1` from the main menu
2. Enter the port number for the tunnel (e.g., `30695`)
3. Provide the WireGuard configuration file path or paste the config
4. The script will:
   - Create a network namespace (`ns-<port>`)
   - Set up WireGuard interface in the namespace
   - Configure routing and iptables rules
   - Extract UUIDs from your panel database
   - Create and start Xray configuration with all UUIDs

### Managing Xray

Use option `2` from the main menu to:
- Start Xray for a specific tunnel
- Stop Xray for a specific tunnel
- Restart Xray for a specific tunnel
- View Xray status and logs

### Auto UUID Refresh

The script includes a background watcher that:
- Automatically reads UUIDs from your panel database every 5 seconds (configurable)
- Only restarts Xray when UUIDs actually change (smart detection)
- Ensures new users can connect immediately without manual intervention
- Works in the background without blocking the main menu

The watcher is automatically started when you run the script and continues running in the background.

### Auto-Restore After Reboot

The script can automatically restore all tunnels after a server reboot:

1. Enable auto-restore during setup wizard, or
2. Use option `8` from the main menu to set up the systemd service

The systemd service (`setup-wg-restore.service`) will:
- Automatically restore all tunnels on boot
- Start the UUID watcher
- Ensure all services are running correctly

To manually test the restore:
```bash
sudo systemctl start setup-wg-restore
```

To disable auto-restore:
```bash
sudo systemctl disable setup-wg-restore
```

## Panel Integration

### Supported Panels

- **x-ui**: Default database path: `/etc/x-ui/x-ui.db`
- **Marzban**: Default database path: `/var/lib/marzban/db.sqlite3`

### UUID Extraction

The script automatically extracts UUIDs from your panel's database:
- For **x-ui**: Reads from the `inbounds` table
- For **Marzban**: Reads from the `users` table and `proxies.settings` JSON field

UUIDs are automatically updated every 5 seconds (configurable) to ensure new users can connect immediately.

## Configuration

Configuration is stored in `/root/.config/wgnm/config.json`:

```json
{
  "panel_type": "marzban",
  "panel_db_path": "/var/lib/marzban/db.sqlite3",
  "uuid_refresh_interval": 5,
  "auto_restore_enabled": true,
  "setup_completed": true
}
```

You can edit this file directly or use the setup wizard to reconfigure.

## File Structure

- **Main Script**: `WGNM.py`
- **Config File**: `/root/.config/wgnm/config.json`
- **UUID Files**: `/tmp/setup-wg-uuids/uuids-<port>.txt`
- **Xray Configs**: `/tmp/xray-<port>.json`
- **Xray Logs**: `/tmp/xray-<port>.log`
- **Debug Log**: `/tmp/setup-wg-watch.log`
- **State Files**: `/tmp/setup-wg-*.state`

## Troubleshooting

### Tunnel Not Connecting

1. Use option `5` (Debug Setup) to check tunnel status
2. Verify WireGuard interface is up: `ip netns exec ns-<port> wg show`
3. Check Xray logs: `tail -f /tmp/xray-<port>.log`
4. Verify UUIDs are loaded: Check `/tmp/setup-wg-uuids/uuids-<port>.txt`

### Xray Not Starting

1. Check if Xray binary exists: `ls -la /usr/local/bin/xray-ns`
2. Check Xray logs: `tail -f /tmp/xray-<port>.log`
3. Verify UUIDs are present in the config: `cat /tmp/xray-<port>.json`
4. Check namespace: `ip netns exec ns-<port> ss -tlnp | grep <port>`

### UUIDs Not Updating

1. Verify panel database path is correct in config
2. Check database file permissions
3. View debug log: `tail -f /tmp/setup-wg-watch.log`
4. Manually trigger refresh: Restart the script or use option `2` to restart Xray

### Tunnels Not Restoring After Reboot

1. Check systemd service status: `systemctl status setup-wg-restore`
2. Check service logs: `journalctl -u setup-wg-restore -n 50`
3. Verify service is enabled: `systemctl is-enabled setup-wg-restore`
4. Manually restore: Use option `6` from the main menu

## Advanced Usage

### Running in Background

To run the UUID watcher in background mode:

```bash
sudo python3 WGNM.py --auto-refresh &
```

Or use the systemd service for persistent background operation.

### Manual UUID Management

UUIDs are stored in `/tmp/setup-wg-uuids/uuids-<port>.txt`, one per line. You can manually edit these files, but they will be overwritten by the auto-refresh watcher.

### Custom Xray Configuration

Xray configurations are generated automatically but stored in `/tmp/xray-<port>.json`. You can modify these files, but they will be regenerated when UUIDs are refreshed.

## Technical Details

### Network Namespaces

Each tunnel runs in its own Linux network namespace (`ns-<port>`), providing complete isolation:
- Separate network interfaces
- Independent routing tables
- Isolated iptables rules
- Independent Xray processes

### UUID Detection

The script uses multiple methods to detect UUID changes:
- MD5 hash comparison of UUID lists
- Database file modification time tracking
- Smart restart only when changes are detected

### Resource Optimization

- Xray is only restarted when UUIDs actually change
- UUID hash and database mtime are persisted across restarts
- Background watcher uses minimal resources

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source. Please refer to the repository for license details.

## Support

For issues, questions, or contributions, please visit:
- GitHub Repository: https://github.com/alihm-us/WireGuard-Namespace-Manager
- Issues: https://github.com/alihm-us/WireGuard-Namespace-Manager/issues

## Acknowledgments

This is a Python port of the original `setup-wg.sh` Bash script, with additional features and improvements.
