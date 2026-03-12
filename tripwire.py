import os
import sys
import time
import datetime
import subprocess
from colorama import Fore, Back, Style
import configparser
import socket
import asyncio
import logging
from logging.handlers import SysLogHandler
import smtplib
from email.message import EmailMessage
from email.mime.text import MIMEText

CONFIG_FILE = "tripwire_config.ini"
CONFIG_REQUIRED_SECTIONS = {
	"General": ["client", "hostname", "allowed_ips"],
	"Syslog": ["host", "port", "path"],
	"Honeypot": ["listen_pairs"],
	"Notifications": ["mail_enabled", "mail_timeout", "cooldown_period", "smtp_server", "smtp_port", "smtp_username", "smtp_password", "sender_email", "recipient_email"],
	"EDR": ["tenant_domain", "location_id"]
}

SERVICE_BANNERS = {
	# --- FTP :21 ---
	# Professional FTP Daemon (Common on Linux/Unix)
	"FTP_ProFTPD_Linux": b"220 ProFTPD 1.3.6 Server (ProFTPD Default Installation) [::ffff:127.0.0.1]\r\n", 
	# Microsoft FTP Service (Common on Windows Server) - Based on your original, slightly refined.
	"FTP_Microsoft": b"220 Microsoft FTP Service\r\n",
	# VSFTPD (Very Secure FTP Daemon) - Very common on Linux distributions
	"FTP_VSFTPD": b"220 (vsFTPd 3.0.3)\r\n", 

	# --- SSH :22 ---
	# Up-to-date banner commonly found on recent Ubuntu/Debian systems
	"SSH_Ubuntu_Current": b"SSH-2.0-OpenSSH_9.3p1 Debian-3ubuntu3.1\r\n", 
	# A slightly older version, still common on enterprise/older systems
	"SSH_CentOS_Older": b"SSH-2.0-OpenSSH_7.4\r\n",
	# OpenSSH on Windows (often found on Windows Server 2016/2019/10/11 with the optional feature)
	"SSH_Windows_OpenSSH": b"SSH-2.0-OpenSSH_7.7\r\n", 

	# --- Telnet :23 ---
	# Cisco IOS Telnet - Highly desirable for luring security researchers or specific attacks
	"Telnet_Cisco_IOS": b"\r\n\r\nCisco IOS Software, C800 Software (C800-UNIVERSALK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc1)\r\nCopyright (c) 1986-2016 by Cisco Systems, Inc.\r\n% Please check for banner login on other ports/protocols\r\nRouter con0 is now available\r\nPress RETURN to get started.\r\n",
	# Basic Linux Telnet daemon banner
	"Telnet_Linux_Simple": b"Welcome to the Telnet Server.\r\n", 

	# --- HTTP :80/443 ---
	# Nginx
	"HTTP_Nginx_Current": (
		b"HTTP/1.1 200 OK\r\n"
		b"Server: nginx/1.25.3\r\n"
		b"Content-Type: text/html\r\n"
		b"Content-Length: 0\r\n\r\n"
	),
	# Apache
	"HTTP_Apache_Linux": (
		b"HTTP/1.1 200 OK\r\n"
		b"Date: Wed, 10 Dec 2025 15:56:27 GMT\r\n"
		b"Server: Apache/2.4.58 (Ubuntu)\r\n"
		b"Last-Modified: Sat, 10 Jun 2023 18:30:00 GMT\r\n"
		b"Content-Length: 0\r\n"
		b"Content-Type: text/html\r\n\r\n"
	),

	# --- MySQL :3306 ---
	# MySQL 8.0.35 Handshake (Slightly newer and more complex version of your original)
	# NOTE: Handshake requires specific capabilities, character set, and authentication plugin data.
	"MYSQL_HANDSHAKE_8_0_35": (
		b'\x4c\x00\x00\x00\x0a'                       # Packet Header (4 bytes) and Protocol Version (1 byte, 0x0a)
		b'8.0.35\x00'                                # Server Version String (Spoofed version)
		b'\x01\x00\x00\x00'                           # Connection ID (Placeholder, should ideally be dynamic)
		b's\x7b\x64\x63\x4f\x6a\x54\x46'              # Auth Data Part 1 (Salt/Scramble - 8 bytes)
		b'\x00\xff\xf7\x08\x02\x00\x00\x00'           # Server Capabilities/Status flags
		b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   # Reserved (10 bytes)
		b'\x10\x00\x00\x00\x00\x00'                   # Extended Capabilities & Filler
		b'S\x6c\x30\x55\x52\x62\x72\x50\x61\x59\x53\x79' # Auth Data Part 2 (Salt/Scramble - 12 bytes)
		b'\x00'                                       # Auth Plugin name length (only present if AUTH_PLUGIN_RESPECT_CAPABILITY is set)
		b'mysql_native_password\x00'                  # Auth Plugin name (Note: mysql_native_password is sometimes used for older clients/versions)
	),

	# --- SMB :445/139 ---
	# The SMB service on port 445 doesn't use a banner in the traditional sense, but the first packet exchange (SMB Negotiate Protocol Request/Response)
	# is critical for OS fingerprinting. The response header contains a Server Component, often listing the OS.
	# The banner below is an *example* of a potential first response payload structure (which is more complex than a simple banner).
	"SMB_Windows_Server_2019": (
		b'\x00' # NetBIOS Session Service layer (Session Message)
		b'\x00\x00\x38' # Length of SMB message (56 bytes)
		b'\xfe\x53\x4d\x42' # SMB 2 Header (Signature)
		# ... rest of the complex SMB2 Negotiation Response packet for a Windows Server 2019 ...
		# (It's too long and complex to represent as a simple banner string here, but essential to note)
		# For a simple honeypot, often just closing the connection after a specific packet or sending a malformed response
		# can be enough to log the scanner's attempt. For a 'banner', just logging the connection is often the best you can do.
		b'SMB_PACKET_SIMULATION' 
	),

	# --- RDP :3389 ---
	# Remote Desktop Protocol: Scanners can identify RDP by the first few bytes, especially the TPKT and X.224 negotiation packets.
	"RDP_Server_Standard": (
		b'\x03\x00\x00\x13' # TPKT Header (Version 3, length 19)
		b'\x0e\xe0\x00\x00' # X.224 Connection Request (CR)
		b'\x00\x00\x00\x01' # Destination/Source Reference (0, 0)
		b'\x00\x00'
		b'\x00\x00' # Class
		b'\x0d\x0a' # CRLF - RDP Negotiation Request (minimal)
	),

	"CustomBanner": b"220 Tripwire Service V1.0 Ready\r\n",
}

app_config = {}

last_mail_alert = 0

def display_banner():
	print(Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)
	print(Fore.YELLOW + "|          TRIPWIRE          |" + Style.RESET_ALL)
	print(Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)

class Utility:
	def __init__(self):
		pass

	@staticmethod
	def clear_cli():
		if sys.platform == "linux" or sys.platform == "linux2":
			subprocess.run(["clear"])
		elif sys.platform == "win32":
			os.system("cls")

	@staticmethod
	def check_privileges():
		if os.getuid() != 0:
			print(Fore.YELLOW + "[WAR]" + Style.RESET_ALL + " Not running as root, some processes may fail.")

	@staticmethod
	def check_os():
		if sys.platform != "linux" and sys.platform != "linux2":
			print(Fore.YELLOW + "[WAR]" + Style.RESET_ALL + " Not running on a Linux system, some features may not function correctly.")
			print(Fore.YELLOW + "[WAR]" + Style.RESET_ALL + " For the best experience run on an Ubuntu device.")

class Config:
	def __init__(self):
		pass

	@staticmethod
	def load_config():
		print(Fore.BLUE + "[INF]" + Style.BRIGHT + " Loading configuration..." + Style.RESET_ALL)

		config = configparser.ConfigParser(interpolation=None)

		# Load configuration file
		if not config.read(CONFIG_FILE):
			print(Fore.RED + "[ERR]" + " Configuration file not found!" + Style.RESET_ALL)
			sys.exit(Fore.BLUE + "[INF]" + Style.BRIGHT + " Exiting application." + Style.RESET_ALL)
		
		print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + f" Configuration loaded from {CONFIG_FILE}." + Style.RESET_ALL)
		
		final_config = {}

		# Error check config
		try:
			for section, keys in CONFIG_REQUIRED_SECTIONS.items():
				
				# Check for missing section
				if section not in config:
					raise KeyError(f"Required section '[{section}]' is missing." + Style.RESET_ALL)

				section_data = config[section]
				
				# Check for missing keys
				for key in keys:
					# The variable for the flattened key
					config_key_flat = f'{section.lower()}_{key}'

					if key not in section_data:
						raise KeyError(f"Required key '{key}' is missing in section '[{section}]'.")

					value = section_data[key]

					# Custom handling for listen_pairs
					if key == 'listen_pairs':
						pairs = []
						
						# Split by the pair separator (;) and remove whitespace
						raw_pairs = [p.strip() for p in value.split(';') if p.strip()]

						for raw_pair in raw_pairs:
							# Split each pair by the separator (:)
							parts = [part.strip() for part in raw_pair.split(':')]

							if len(parts) != 3:
								raise ValueError(f"Invalid format in listen_pairs: '{raw_pair}'. Expected PORT:SERVICE:PROTOCOL.")

							port_str, service_name, protocol_str = parts

							try:
								port = int(port_str)
							except ValueError:
								raise ValueError(f"Port '{port_str}' is not a valid integer.")

							protocol = protocol_str.upper()
							if protocol not in ['TCP', 'UDP']:
								raise ValueError(f"Protocol '{protocol_str}' is invalid. Must be TCP or UDP.")

							if service_name not in SERVICE_BANNERS:
								raise ValueError(f"Service '{service_name}' has no defined banner in SERVICE_BANNERS dictionary.")

							# Add the parsed pair: [(port, service, protocol), ...]
							pairs.append((port, service_name, protocol))

						final_config[config_key_flat] = pairs
					
					# Custom handling for allowed_ips
					elif key == 'allowed_ips':
						# Parse comma-separated IPs into a list, stripping whitespace
						ips = [ip.strip() for ip in value.split(',') if ip.strip()]
						final_config[config_key_flat] = ips

					else:
						final_config[config_key_flat] = value

		except (KeyError, ValueError) as error:
			# Catch both structural (KeyError) and parsing (ValueError) issues
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" Configuration validation error: {error}")
			sys.exit(Fore.BLUE + "[INF]" + Style.BRIGHT + " Exiting application due to configuration issues.")

		return final_config

	@staticmethod
	def edit_config():
		Utility.clear_cli()
		print(Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)
		print(Fore.YELLOW + "|    CONFIGURATION EDITOR    |" + Style.RESET_ALL)
		print(Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)
		
		try:
			app_config = Config.load_config()
		except SystemExit:
			return

		print("")

		new_settings = {}

		for section, keys in CONFIG_REQUIRED_SECTIONS.items():
			print(Style.BRIGHT + f"[{section}]" + Style.RESET_ALL)

			for key in keys:
				config_key = section.lower() + "_" + key.lower()
				
				# Custom handling for listen_pairs
				if key == 'listen_pairs':
					current_value = "; ".join([f"{p}:{s}:{pr}" for p, s, pr in app_config[config_key]])
					print(f"{section} {key} (Format: PORT:SERVICE:PROTOCOL;...): {current_value}")
				elif key == 'allowed_ips':
					current_value = ", ".join(app_config[config_key])
					print(f"{section} {key} (Format: IP1, IP2, ...): {current_value}")
				else:
					current_value = app_config[config_key]
					print(f"{section} {key}: {current_value}")

				if input("Modify value? (y/n): ").lower() == "y":
					if key == 'listen_pairs':
						new_value = input(f"{section} {key} [ENTER NEW STRING]: ")
					elif key == 'allowed_ips':
						new_value = input(f"{section} {key} [ENTER IP LIST]: ")
					else:
						new_value = input(f"{section} {key}: ")
						
					new_settings[config_key] = new_value
				else:
					if key == 'listen_pairs':
						new_settings[config_key] = current_value
					else:
						new_settings[config_key] = current_value

				print("")

		if input("Save changes? (y/n): ").lower() == 'y':
			print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + " Configuration saved.")
			Config.save_config(new_settings)
		else:
			print(Fore.BLUE + "[INF]" + Style.RESET_ALL + " Configuration edit cancelled.")
			return None

		# Clear and return to main menu
		Utility.clear_cli()

	@staticmethod
	def save_config(config_data):
		config = configparser.ConfigParser()
	
		# Re-structure the flat dictionary into sections for saving
		save_sections = {}

		for key, value in config_data.items():
			section, name = key.split('_', 1)
			section = section.title()

			# Custom handling for listen_pairs during saving
			if name == 'listen_pairs':
				if isinstance(value, list):
					final_value = "; ".join([f"{p}:{s}:{pr}" for p, s, pr in value])
				else:
					final_value = str(value)
			# Custom handling for allowed_ips during saving
			elif name == 'allowed_ips':
				if isinstance(value, list):
					final_value = ", ".join(value)
				else:
					final_value = str(value)
			else:
				final_value = str(value)

			if section not in save_sections:
				save_sections[section] = {}

			# Store the final string value for the INI file
			save_sections[section][name] = final_value

		for section_name, section_dict in save_sections.items():
			config[section_name] = section_dict

		try:
			with open(CONFIG_FILE, 'w') as f:
				config.write(f)
			return True
		except IOError:
			return False

class Persistence:
	def __init__(self):
		pass

	@staticmethod
	def install_systemd_service():
		Utility.clear_cli()
		print(Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)
		print(Fore.YELLOW + "|      SERVICE INSTALLER     |" + Style.RESET_ALL)
		print(Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)
		
		# Platform check
		if sys.platform != "linux" and sys.platform != "linux2":
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + " Persistence is only available on Linux systems.")
			input("\nPress Enter to return...")
			return

		# Privileges check
		if os.getuid() != 0:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + " Root privileges required to install systemd services.")
			input("\nPress Enter to return...")
			return

		script_path = os.path.abspath(__file__)
		script_dir = os.path.dirname(script_path)
		python_path = sys.executable
		service_name = "tripwire"
		service_file_path = f"/etc/systemd/system/{service_name}.service"
		
		print(Fore.BLUE + "[INF]" + Style.BRIGHT + f" Detected Script Path: {script_path}" + Style.RESET_ALL)
		print(Fore.BLUE + "[INF]" + Style.BRIGHT + f" Detected Python Path: {python_path}" + Style.RESET_ALL)
		print("")

		service_content = f"""[Unit]
Description=Tripwire Honeypot Service
After=network.target syslog.service

[Service]
Type=simple
User=root
WorkingDirectory={script_dir}
ExecStart={python_path} {script_path} --headless
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier={service_name}

[Install]
WantedBy=multi-user.target
"""
		
		print(Style.DIM + service_content + Style.RESET_ALL)
		print("-" * 30)

		if input("Install this service? (y/n): ").lower() != 'y':
			print(Fore.BLUE + "[INF]" + Style.RESET_ALL + " Installation cancelled.")
			time.sleep(1)
			return

		try:
			print(Fore.BLUE + "\n[INF]" + Style.BRIGHT + " Creating service file..." + Style.RESET_ALL)
			with open(service_file_path, "w") as f:
				f.write(service_content)
				
			print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + f" Service file created at {service_file_path}")
			
			# Reload daemon
			print(Fore.BLUE + "[INF]" + Style.BRIGHT + " Reloading systemd daemon..." + Style.RESET_ALL)
			subprocess.run(["systemctl", "daemon-reload"], check=True)
			
			# Enable service
			print(Fore.BLUE + "[INF]" + Style.BRIGHT + " Enabling service..." + Style.RESET_ALL)
			subprocess.run(["systemctl", "enable", service_name], check=True)
			print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + f" Service '{service_name}' enabled (autostart on boot).")
			
			print("-" * 30)
			print(Fore.GREEN + Style.BRIGHT + "INSTALLATION COMPLETE" + Style.RESET_ALL)
			print(Fore.BLUE + "[INF]" + Style.RESET_ALL + f" Start the service: systemctl start {service_name}")
			print(Fore.BLUE + "[INF]" + Style.RESET_ALL + f" Check status:      systemctl status {service_name}")
			print(Fore.BLUE + "[INF]" + Style.RESET_ALL + f" View logs:         journalctl -u {service_name} -f")
			
		except Exception as error:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" Failed to install service: {error}")
			
		input("\nPress Enter to return to main menu...")

class Banner:
	def __init__(self):
		pass

	@staticmethod
	def view_banner(banner_name, banner_data):
		Utility.clear_cli()
		print(Fore.YELLOW + "+------------------------------+" + Style.RESET_ALL)
		print(Fore.YELLOW + "|  AVAILABLE SERVICE BANNERS   |" + Style.RESET_ALL)
		print(Fore.YELLOW + "+------------------------------+" + Style.RESET_ALL)
		print(Fore.YELLOW + f">  VIEWING BANNER: {banner_name:<11}" + Style.RESET_ALL)

		try:
			decoded_banner = banner_data.decode('utf-8').strip().replace('\r\n', ' [CRLF] ')
			print(Fore.GREEN + Style.BRIGHT + "Type: Text/ASCII" + Style.RESET_ALL)
			print("-" * 40)
			print(decoded_banner)
			print("-" * 40)
			
		except UnicodeDecodeError:
			print(Fore.RED + Style.BRIGHT + "Type: Binary/Protocol Handshake" + Style.RESET_ALL)
			print(Fore.RED + "WARNING: Cannot display binary data directly as text." + Style.RESET_ALL)
			print("-" * 40)
			print("Raw Hexadecimal Data:")

			print(banner_data.hex())
			print("-" * 40)
			
		input("\nPress Enter to return to the Banner List...")

	@staticmethod
	def banner_menu():
		banner_names = list(SERVICE_BANNERS.keys())
		
		while True:
			Utility.clear_cli()
			print(Fore.YELLOW + "+------------------------------+" + Style.RESET_ALL)
			print(Fore.YELLOW + "|  AVAILABLE SERVICE BANNERS   |" + Style.RESET_ALL)
			print(Fore.YELLOW + "+------------------------------+" + Style.RESET_ALL)
			
			for i, name in enumerate(banner_names):
				print(f"{i + 1}. {name}")
				
			print("-" * 30)
			print("0. Return to Main Menu")
			print("-" * 30)
			
			choice = input("Select a banner number (1-{}) or 0: ".format(len(banner_names))).strip()
			
			try:
				choice_index = int(choice)
				
				if choice_index == 0:
					Utility.clear_cli()
					return

				elif 1 <= choice_index <= len(banner_names):
					selected_name = banner_names[choice_index - 1]
					selected_data = SERVICE_BANNERS[selected_name]
					
					Banner.view_banner(selected_name, selected_data) # Call the viewer function
					
				else:
					print(Fore.RED + "[ERR]" + Style.RESET_ALL + " Invalid number selected.")
					time.sleep(1)
					
			except ValueError:
				print(Fore.RED + "[ERR]" + Style.RESET_ALL + " Invalid input. Please enter a number.")
				time.sleep(1)

class Syslog:
	def __init__(self):
		pass

	@staticmethod
	def setup_syslog_logger(config):
		global tripwire_logger
		
		syslog_host = config['syslog_host']
		syslog_port = int(config['syslog_port'])
		
		logger = logging.getLogger('TripwireLogger')
		logger.setLevel(logging.INFO)
		
		# Prevent logging messages from duplicating via the root handler
		logger.propagate = False

		# Create SysLogHandler
		try:
			handler = SysLogHandler(address=(syslog_host, syslog_port), facility=SysLogHandler.LOG_LOCAL1, socktype=socket.SOCK_STREAM)
			formatter = logging.Formatter('%(name)s: %(message)s')
			handler.setFormatter(formatter)
			logger.addHandler(handler)
			
			tripwire_logger = logger
			print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + f" Syslog logging initialised at {syslog_host}:{syslog_port}.")
			return logger
			
		except Exception as error:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" Failed to set up Syslog logger: {error}")
			return None

	@staticmethod
	def check_syslog_config():
		global app_config

		Utility.clear_cli()
		print(Fore.YELLOW + "+------------------------------+" + Style.RESET_ALL)
		print(Fore.YELLOW + "|     SYSLOG CONFIGURATION     |" + Style.RESET_ALL)
		print(Fore.YELLOW + "+------------------------------+" + Style.RESET_ALL)
		print("")
		print(Fore.BLUE + "[INF]" + Style.BRIGHT + " Loading configuration..." + Style.RESET_ALL)
		Utility.check_privileges()
		Utility.check_os()
		Syslog.check_rsyslog_service_status()
		print("")

		syslog_config_file = app_config['syslog_path']

		# What to check for
		tcp_module = "module(load=\"imtcp\")"
		tcp_input = "input(type=\"imtcp\" port=\"" + app_config["syslog_port"] + "\")"
		udp_module = "module(load=\"imudp\")"
		udp_input = "input(type=\"imudp\" port=\""

		try:
			with open(syslog_config_file, 'r') as f:
				lines = f.readlines()

			# Check for the required TCP module line
			tcp_module_found = any(line.strip() == tcp_module for line in lines)

			# Check for the required TCP input line
			tcp_input_found = any(line.strip() == tcp_input for line in lines)

			if tcp_module_found and tcp_input_found:
				print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + f" Required TCP configurations are present.")
			else:
				if not tcp_module_found:
					print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" TCP configuration missing or commented out: {tcp_module}")
				if not tcp_input_found:
					print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" TCP configuration missing, incorrect or commented out: {tcp_input}")

			for i, line in enumerate(lines):
				line_stripped = line.strip()

				# Check for UDP lines, ignoring lines that start with '#'
				if line_stripped.startswith(udp_module) or line_stripped.startswith(udp_input):

					# Check if the line is NOT commented out
					if not line_stripped.startswith("#"):
						print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" UDP configuration active: {line_stripped}")

		except FileNotFoundError:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" Config file was not found at {syslog_config_file}")
		except Exception as error:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + f"An unexpected error occurred: {error}")

		print("")
		input("Press any key to return to main menu:")
		Utility.clear_cli()
		return

	@staticmethod
	def check_rsyslog_service_status():
		command = ["systemctl", "is-active", "rsyslog"]

		try:
			result = subprocess.run(
				command, 
				capture_output=True, 
				text=True, 
				timeout=5
			)

			if result.returncode == 0:
				print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + f" rsyslog service is running.")
				return True
			elif result.returncode == 3:
				print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" rsyslog service is inactive or failed.")
				print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" Systemctl output: {result.stdout.strip()}")
				return False
			else:
				print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" Unexpected systemctl return code: {result.returncode}")
				print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" {result.stderr.strip()}")
				return False

		except FileNotFoundError:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + " 'systemctl' command not found. Are you on a systemd-based Linux?")
			return False
		except subprocess.TimeoutExpired:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + " System command timed out.")
			return False
		except Exception as error:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" An unexpected error occurred: {error}")
			return False

class Mail:
	def __init__(self):
		pass

	@staticmethod
	def send_mail_notification(log_message):
		global app_config
		global last_mail_alert

		if app_config["notifications_mail_enabled"] != "1":
			return

		cooldown_seconds = int(app_config["notifications_cooldown_period"])
		cooldown_target = last_mail_alert + cooldown_seconds
		current_unix_timestamp = datetime.datetime.now(datetime.UTC).timestamp()

		if current_unix_timestamp <= cooldown_target:
			return

		message = EmailMessage()
		message["Subject"] = "TRIPWIRE triggered at " + app_config["general_client"]
		message["From"] = app_config["notifications_sender_email"]
		message["To"] = app_config["notifications_recipient_email"]


		# generate EDR location URL
		edr_location_link = ""
		if app_config["edr_location_id"] != None and app_config["edr_location_id"] != "" and app_config["edr_tenant_domain"] != None and app_config["edr_tenant_domain"] != "":
			edr_location_link = "<p>EDR Client Location: <a href=\"https://" + app_config["edr_tenant_domain"] + "/organizations/locations/" + app_config["edr_location_id"] + "\">https://" + app_config["edr_tenant_domain"] + "/organizations/locations/" + app_config["edr_location_id"] + "</a></p>"

		html_body = f"""\
		<html>
			<head></head>
			<body>
				<p><strong>TRIPWIRE was triggered for {app_config["general_client"]}</strong></p>
				<br>
				<p><strong>Log:</strong></p>
				<p>{log_message}</p>
				<br>
				{edr_location_link}
			</body>
		</html>
		"""

		message.set_content(html_body, subtype="html")

		try:
			connection = smtplib.SMTP_SSL(
				host = app_config["notifications_smtp_server"],
				port = int(app_config["notifications_smtp_port"]),
				timeout = int(app_config["notifications_mail_timeout"])
			)

			connection.login(
				app_config["notifications_smtp_username"],
				app_config["notifications_smtp_password"]
			)

			try:
				connection.sendmail(app_config["notifications_sender_email"], app_config["notifications_recipient_email"], message.as_string())

				last_mail_alert = datetime.datetime.now(datetime.UTC).timestamp()
				print(Fore.BLUE + "[INF]" + Style.RESET_ALL + " Mail Notification sent: (" + app_config["notifications_sender_email"] + ", " + app_config["notifications_recipient_email"] + ")")
			finally:
				connection.quit()
		except Exception as error:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" Mail failed to send: {error}")

class TcpHoneypot:
	def __init__(self):
		pass

	async def handle_tcp_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
		# Handles a single zero-interaction TCP connection
		address = writer.get_extra_info('peername')
		attacker_ip, attacker_port = address[0], address[1]
		target_port = writer.get_extra_info('sockname')[1]
		
		# Check Allowlist
		if attacker_ip in app_config.get('general_allowed_ips', []):
			if tripwire_logger:
				tripwire_logger.debug(f"Connection ignored from allowed IP. IP={attacker_ip} Port={target_port}")
			
			writer.close()
			await writer.wait_closed()
			return
		
		# Determine which service name was used to launch this listener
		banner_data = None
		for _, service_name, protocol in app_config['honeypot_listen_pairs']:
			if protocol == 'TCP' and target_port == _:
				banner_data = SERVICE_BANNERS.get(service_name)
				break

		log_message = f"TCP connection received. TargetPort={target_port} SourceIP={attacker_ip}"
		captured_data_log = ""

		if banner_data:
			try:
				# Send the service banner
				writer.write(banner_data)
				await writer.drain() 
				
				# Wait briefly for a response (e.g., username/password)
				data = await asyncio.wait_for(reader.read(1024), timeout=1.5) 
				
				if data:
					captured_data_log = f" CapturedData='{data.decode(errors='ignore').strip()}'"

			except asyncio.TimeoutError:
				captured_data_log = "CapturedData='None (Timeout)'"

			except ConnectionResetError:
				captured_data_log = "ConnectionReset='True'"
	            
			except UnicodeDecodeError:
				captured_data_log = "CapturedData='Binary/Undecodable Bytes'"
		
		# Log the event
		if tripwire_logger:
			tripwire_logger.info(log_message + captured_data_log, extra={'target_port': target_port, 'source_ip': attacker_ip})
			print(Fore.YELLOW + "[HIT]" + Style.RESET_ALL + " Event occurred: " + log_message)
		else:
			print(Fore.RED + "[ERR] " + Style.RESET_ALL + log_message)

		# Send email notification
		Mail.send_mail_notification(log_message + captured_data_log)

		# Close the connection
		writer.close()
		await writer.wait_closed()

class UdpHoneypot(asyncio.DatagramProtocol):
	def __init__(self, target_port, service_name):
		self.target_port = target_port
		self.service_name = service_name

	def connection_made(self, transport):
		self.transport = transport

	def datagram_received(self, data, addr):
		attacker_ip, attacker_port = addr

		# Check Allowlist
		if attacker_ip in app_config.get('general_allowed_ips', []):
			if tripwire_logger:
				tripwire_logger.debug(f"Datagram ignored from allowed IP. IP={attacker_ip} Port={self.target_port}")
			return

		log_message = f"UDP datagram received. TargetPort={self.target_port} SourceIP={attacker_ip}"

		try:
			captured_data_log = f" CapturedData='{data.decode(errors='ignore').strip()}'"
		except UnicodeDecodeError:
			captured_data_log = f" CapturedData='Binary/Undecodable Bytes'"

		if tripwire_logger:
			tripwire_logger.info(log_message + captured_data_log)
			print(Fore.YELLOW + "[HIT]" + Style.RESET_ALL + " Event occurred: " + log_message)
		else:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + log_message)

		# Send email notification
		Mail.send_mail_notification(log_message + captured_data_log)

async def start_multiple_listeners(listen_pairs):
	# Launches concurrent TCP and UDP listeners
	tasks = []
	
	for port, service, protocol in listen_pairs:
		try:
			if protocol == "TCP":
				# Start a TCP Server
				server = await asyncio.start_server(
					TcpHoneypot.handle_tcp_connection, "0.0.0.0", port
				)

				tasks.append(server.serve_forever())
				print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + f" Listening on TCP port {port} (Service: {service})")
				
			elif protocol == "UDP":
				# Start a UDP Listener
				transport, protocol_instance = await asyncio.get_event_loop().create_datagram_endpoint(
					lambda: UdpHoneypot(port, service), local_addr=('0.0.0.0', port)
				)

				# Store the transport handle to keep the task alive
				tasks.append(transport.close()) 
				print(Fore.GREEN + "[SUC]" + Style.RESET_ALL + f" Listening on UDP port {port} (Service: {service})")

		except OSError as error:
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" Could not bind {protocol} port {port}: {error.strerror}")

	if not tasks:
		print(Fore.RED + "[ERR]" + Style.RESET_ALL + " No honeypots successfully started.")
		return

	# Keep the main loop running until interrupted
	await asyncio.gather(*tasks)

def start_honeypot(headless=False):
	global app_config	
	listen_pairs = app_config.get('honeypot_listen_pairs')
	
	if not listen_pairs:
		print(Fore.RED + "[ERR]" + Style.RESET_ALL + " No listening pairs configured.")
		return

	# Setup logging
	Syslog.check_rsyslog_service_status()
	Syslog.setup_syslog_logger(app_config) 
	
	print(Fore.CYAN + "\n[SUC]" + Style.RESET_ALL + " All honeypots active. Press Ctrl+C to stop.")
	
	try:
		# Start the async event loop
		asyncio.run(start_multiple_listeners(listen_pairs))
		
	except KeyboardInterrupt:
		print(Fore.YELLOW + "\n[WAR]" + Style.RESET_ALL + " All honeypots stopped by user.")
	except Exception as error:
		print(Fore.RED + "[ERR]" + Style.RESET_ALL + f" An unhandled error occurred during runtime: {error}")

	if not headless:
		input("Press any key to return to main menu:")
		Utility.clear_cli()
	return

def startup():
	display_banner()
	Utility.clear_cli()

def main_menu():
	global app_config

	while True:
		try:
			app_config = Config.load_config()
		except SystemExit:
			return

		print("\n" + Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)
		print(Fore.YELLOW + "|          TRIPWIRE          |" + Style.RESET_ALL)
		print(Fore.YELLOW + "+----------------------------+" + Style.RESET_ALL)
		print("")
		Utility.check_privileges()
		Utility.check_os()
		Syslog.check_rsyslog_service_status()
		print("")
		print(f"Syslog Target: {app_config['syslog_host']}:{app_config['syslog_port']}")
		print("Honeyed Ports: " + ", ".join([f"{port}:{service}:{protocol}" for port, service, protocol in app_config['honeypot_listen_pairs']]))
		print("")
		print("-" * 30)
		print("1. Start Honeypot")
		print("2. Edit Configuration")
		print("3. Check Syslog Config")
		print("4. View Services")
		print("5. Install Persistence (Systemd)")
		print("-" * 30)
		print("0. Exit Application")
		print("-" * 30)

		choice = input("Select an option (1-4): ").strip()

		if choice == "1":
			start_honeypot()
		elif choice == "2":
			Config.edit_config()
		elif choice == "3":
			Syslog.check_syslog_config()
		elif choice == "4":
			Banner.banner_menu()
		elif choice == "5":
			Persistence.install_systemd_service()
		elif choice == "0":
			print(Fore.BLUE + "[INF]" + Style.BRIGHT + " Shutting down." + Style.RESET_ALL)
			break
		else:
			Utility.clear_cli()
			print(Fore.RED + "[ERR]" + Style.RESET_ALL + " Invalid choice. Please select 1, 2, or 3." + Style.RESET_ALL)

if __name__ == "__main__":
	if len(sys.argv) > 1 and sys.argv[1] == "--headless":
		# Headless / Service Mode
		app_config = Config.load_config()
		start_honeypot(headless=True)
	else:
		# Interactive Mode
		Utility.clear_cli()
		startup()
		main_menu()