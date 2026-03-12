# Tripwire

Tripwire is a lightweight, multi-protocol honeypot designed to simulate various network services and log unauthorised access attempts. It acts as a "tripwire," providing early warning of scanning or intrusion activities on your network.

This tool will not simulate a full operating system to let you monitor threat actors, but will simulate the services that run on an operating system to make it appear as a legitimate target.

## Capabilities

- **Multi-Protocol Support**: Simultaneous listening on multiple TCP and UDP ports.
- **Service Simulation**: Service banner simulations for common services:
  - **FTP**: ProFTPD, Microsoft FTP, VSFTPD.
  - **SSH**: Ubuntu OpenSSH, CentOS OpenSSH.
  - **Telnet**: Cisco IOS, Linux.
  - **SMTP**: Postfix (Ubuntu), Microsoft Exchange.
  - **HTTP/HTTPS**: Nginx, Apache.
  - **Databases**: MySQL 8.0, PostgreSQL.
  - **Infrastructure**: SMB (Windows Server), RDP, VNC.
- **Interactive Configuration**: Built-in CLI tool for editing settings and viewing available service banners.
- **Advanced Logging**:
  - **Syslog**: Integration with `rsyslog` for centralized logging.
  - **Tripwire Alerts**: Instant email notifications when a connection is detected (with cooldown protection).
- **EDR Integration**: Direct links to Infocyte EDR client locations for rapid incident response.
- **Persistence**: Easily install as a `systemd` service on Linux for automatic start on boot.
- **Security**: IP allowlisting to prevent internal scans from triggering alerts.

## Setup Guide

### Prerequisites

- **Python 3.x**
- **Dependencies**: Install required Python packages.
  ```bash
  pip install colorama
  ```
- **OS**: While Tripwire includes some cross-platform support, it is optimized for **Ubuntu/Linux** (especially for Syslog and Persistence features).

### 1. Configuration

1.  Copy the example configuration file:
    ```bash
    cp tripwire_config.ini.orig tripwire_config.ini
    ```
2.  Edit `tripwire_config.ini` to match your environment. You can do this manually or use the built-in editor:
    ```bash
    python tripwire.py
    ```
    *Note: Select the configuration editor from the main menu.*

### 2. Running Tripwire

To start the honeypot in interactive mode:
```bash
python tripwire.py
```

To run in **headless mode** (typical for background services):
```bash
python tripwire.py --headless
```

### 3. Persistence (Linux Only)

To install Tripwire as a system service that starts on boot:
1. Run Tripwire as root.
2. Select the **Service Installer** option from the main menu.
3. Once installed, manage the service with `systemctl`:
   ```bash
   sudo systemctl start tripwire
   sudo systemctl enable tripwire
   ```

## Usage & Menus

- **1. Start Honeypot**: Launches all configured listeners.
- **2. Configuration Editor**: Update IPs, ports, and notification settings.
- **3. View Service Banners**: Preview what attackers will see.
- **4. Syslog Configuration**: Check the health and configuration of local `rsyslog`.
- **5. Persistence**: Manage the `systemd` unit.

## Security Note

Running a honeypot involves opening ports to the network. Ensure that Tripwire is running on a dedicated or isolated system, and always use the IP allowlist (`allowed_ips` in config) for your management stations to avoid false positives.

