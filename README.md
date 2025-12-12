# WireGuard Namespace Manager (WGNM)

[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A powerful tool for managing multiple isolated WireGuard tunnels and Xray proxy instances using Linux Network Namespaces. Each tunnel runs in its own namespace with automatic Xray configuration.

## ✨ Features

- 🔒 **Complete Isolation**: Each WireGuard tunnel runs in its own network namespace
- 🚀 **Xray Support**: Automatic Xray setup for each namespace
- 🔄 **Auto UUID Refresh**: UUIDs are automatically read from panel (Marzban/x-ui) and updated
- 📊 **Easy Management**: Simple and intuitive interactive menu
- 🔧 **Auto-Restore**: Automatic tunnel restoration after system reboot
- ⚡ **Background Service**: Runs as a systemd service in the background
- 🎯 **Multi-Panel Support**: Supports both Marzban and x-ui panels
- 🔐 **Secure**: Uses proper command execution with security best practices

## 📋 Requirements

- Linux (tested on Ubuntu/Debian)
- Python 3.6 or higher
- Root access
- WireGuard kernel module
- Network tools: `iproute2`, `iptables`

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/alihm-us/WireGuard-Namespace-Manager.git
cd WireGuard-Namespace-Manager
```

### 2. Install Dependencies

The script automatically checks and installs required dependencies:

```bash
sudo python3 WGNM.py
```

On first run, the script will check for the following dependencies:
- `wireguard-tools`
- `iproute2`
- `iptables`
- `curl`
- WireGuard kernel module

### 3. Create Shortcut (Optional)

For easier access, you can create a symlink:

```bash
sudo ln -s /path/to/WGNM.py /usr/local/bin/WGNM
sudo chmod +x /usr/local/bin/WGNM
```

Now you can run the script from anywhere by typing `WGNM`.

## 📖 Usage

### Running the Script

```bash
sudo WGNM
```

Or:

```bash
sudo python3 WGNM.py
```

### Main Menu

After running, you'll see the following menu:

```
╔════════════════════════════════════════════════════╗
║        WireGuard Namespace Manager                 ║
╚════════════════════════════════════════════════════╝

1. Create New Setup
2. Manage Xray
3. Restart WireGuard
4. Delete Setup
5. Debug Setup
6. Restore All Tunnels
7. Restore Tunnel from Config File
8. Setup Auto-Restore
9. Exit
```

### Setup Wizard

On first run, a setup wizard will guide you through:

1. **Panel Selection**: Choose between x-ui or Marzban
2. **Database Path**: Path to your panel's database file
3. **UUID Refresh Interval**: How often to check for UUID updates (default: 5 seconds)
4. **Auto-Restore**: Enable automatic tunnel restoration after reboot

### Creating a New Tunnel

1. Select option `1` from the main menu
2. Enter the path to your WireGuard config file
3. Enter the port number
4. The script will automatically:
   - Create a namespace
   - Configure WireGuard
   - Start Xray
   - Load UUIDs from the panel

### Managing Xray

Option `2` from the main menu allows you to:
- View Xray status in all namespaces
- Start/Stop Xray
- Manually refresh UUIDs

### Auto-Restore

Option `8` from the main menu:
- Creates a systemd service for automatic tunnel restoration after reboot

## 🔧 Advanced Commands

### Run Auto-Refresh

```bash
sudo WGNM --auto-refresh
```

Or:

```bash
sudo WGNM --watch
```

This runs the script in background mode and automatically refreshes UUIDs.

### Restore Tunnels

```bash
sudo WGNM --restore
```

Restores all saved tunnels (typically used by systemd service).

### Start Watcher

```bash
sudo WGNM --start-watcher
```

Starts the UUID watcher in the background.

## 📁 File Structure

```
/root/WGNM.py                    # Main script
/etc/setup-wg/
  ├── config.json                # Main configuration
  └── tunnels/                   # Tunnel information
/tmp/
  ├── setup-wg-watch.log         # Watcher logs
  ├── setup-wg-uuids/            # UUID files
  └── xray-*.json                # Xray configs
/etc/systemd/system/
  ├── setup-wg-restore.service    # Auto-restore service
  └── setup-wg-uuid-watcher.service  # UUID watcher service
```

## 🔍 How It Works

### Network Namespaces

Each WireGuard tunnel runs in its own Linux network namespace (`ns-{port}`), providing complete network isolation. This allows multiple tunnels to run simultaneously without conflicts.

### UUID Management

The script automatically:
1. Reads UUIDs from your panel database (Marzban or x-ui)
2. Detects changes by comparing hashes
3. Updates Xray configurations when UUIDs change
4. Restarts Xray services to apply changes

### Background Services

Two systemd services are available:

1. **setup-wg-restore.service**: Restores all tunnels after system reboot
2. **setup-wg-uuid-watcher.service**: Continuously monitors and updates UUIDs

## 🔍 Troubleshooting

### Tunnels Not Showing in List

If tunnels are not displayed in the list:

1. Check if namespaces exist:
   ```bash
   ip netns list
   ```

2. Check logs:
   ```bash
   tail -f /tmp/setup-wg-watch.log
   ```

### UUIDs Not Updating

1. Check service status:
   ```bash
   systemctl status setup-wg-uuid-watcher.service
   ```

2. Check logs:
   ```bash
   tail -f /tmp/setup-wg-watch.log
   ```

3. Verify database path in config:
   ```bash
   cat /etc/setup-wg/config.json
   ```

### Command Execution Errors

If commands fail:

1. Verify root access:
   ```bash
   sudo -v
   ```

2. Check dependencies:
   ```bash
   which wg ip iptables curl
   ```

### Service Not Starting

If the UUID watcher service fails to start:

1. Check service logs:
   ```bash
   journalctl -u setup-wg-uuid-watcher.service -n 50
   ```

2. Verify Python path:
   ```bash
   which python3
   ```

3. Check script permissions:
   ```bash
   ls -la /root/WGNM.py
   ```

## 🛠️ Development

### Code Structure

- `run_cmd()`: Execute shell commands securely
- `create_setup()`: Create new tunnel
- `manage_xray()`: Manage Xray instances
- `refresh_uuids_for_all_namespaces()`: Update UUIDs
- `extract_uuids_from_sqlite()`: Extract UUIDs from database
- `ensure_uuid_watcher_service()`: Setup systemd service

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style

- Follow PEP 8 style guide
- Use type hints where possible
- Add docstrings to functions
- Write clear commit messages

## 📝 Configuration

### Config File Location

`/etc/setup-wg/config.json`

### Example Config

```json
{
  "panel_type": "marzban",
  "panel_db_path": "/var/lib/marzban/db.sqlite3",
  "uuid_refresh_interval": 5,
  "auto_restore_enabled": true,
  "setup_completed": true
}
```

## 🔐 Security Considerations

- The script requires root access to manage network namespaces
- Database files are read in read-only mode
- Commands are executed with proper quoting to prevent injection
- Systemd services run as root (required for network operations)

## 📊 Performance

- UUID refresh interval is configurable (default: 5 seconds)
- Changes are detected using hash comparison for efficiency
- Only restarts Xray when UUIDs actually change
- Background services use minimal resources

## 🧪 Testing

To test the script:

1. Create a test WireGuard config
2. Run the setup wizard
3. Create a tunnel
4. Verify namespace creation:
   ```bash
   ip netns list
   ```
5. Check Xray status in the menu

## 📚 Documentation

- [WireGuard Documentation](https://www.wireguard.com/)
- [Xray Documentation](https://xtls.github.io/)
- [Linux Network Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)

## 📝 License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## 🙏 Acknowledgments

- [WireGuard](https://www.wireguard.com/) - VPN protocol
- [Xray](https://github.com/XTLS/Xray-core) - Proxy tool
- [Marzban](https://github.com/Gozargah/Marzban) - Management panel
- [x-ui](https://github.com/vaxilu/x-ui) - Management panel

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/alihm-us/WireGuard-Namespace-Manager/issues)
- **Discussions**: [GitHub Discussions](https://github.com/alihm-us/WireGuard-Namespace-Manager/discussions)

## ⚠️ Warning

This tool requires root access and makes changes to system network configuration. Please test it in a safe environment before using in production.

## 🗺️ Roadmap

- [ ] Support for more panel types
- [ ] Web UI for management
- [ ] Docker support
- [ ] Better error handling and recovery
- [ ] Performance optimizations

---

**Note**: This project is a Python port of the original Bash script `setup-wg.sh` and maintains feature parity with it.
