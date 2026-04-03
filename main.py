#!/usr/bin/env python3
"""
SSH Honeypot - Advanced security research tool for capturing and analyzing SSH attack patterns.

Features:
- SSH honeypot with realistic shell emulation
- HTTP/WordPress login honeypot
- Tarpit mode to slow down attackers
- Session recording with keystroke timing
- Download/malware URL trapping
- Fake privilege escalation (sudo works!)
- Bot vs human detection
- Webhook alerts
- Analytics dashboard
"""

import argparse
import json
import logging
import os
import re
import socket
import sys
import threading
import time
import uuid
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional
from statistics import mean, stdev

import paramiko

# =============================================================================
# CONFIGURATION
# =============================================================================

# Directory setup
BASE_DIR = Path(__file__).parent
LOG_DIR = BASE_DIR / "logs"
STATIC_DIR = BASE_DIR / "static"
SESSIONS_DIR = LOG_DIR / "sessions"

# Create directories if they don't exist
LOG_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)
SESSIONS_DIR.mkdir(exist_ok=True)

# Log file paths
CREDS_LOG = LOG_DIR / "credentials.log"
COMMANDS_LOG = LOG_DIR / "commands.log"
HTTP_LOG = LOG_DIR / "http_attempts.log"
DOWNLOADS_LOG = LOG_DIR / "malware_urls.log"
ALERTS_LOG = LOG_DIR / "alerts.log"

# SSH Configuration
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
SERVER_KEY_PATH = STATIC_DIR / "server.key"

# Fake system configuration
FAKE_HOSTNAME = "corp-server01"
FAKE_USERNAME = "sysadmin"
FAKE_WORKING_DIR = "/home/sysadmin"

# Alert configuration (set via CLI or environment)
WEBHOOK_URL = os.environ.get("HONEYPOT_WEBHOOK_URL", "")

# =============================================================================
# LOGGING SETUP
# =============================================================================


class ColoredFormatter(logging.Formatter):
    """Formatter that adds colors to console output."""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m"
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        reset = self.COLORS["RESET"]
        record.msg = f"{color}{record.msg}{reset}"
        return super().format(record)


def setup_logging():
    """Configure all loggers for the honeypot."""

    # Credentials logger
    creds_logger = logging.getLogger("CredentialsLogger")
    creds_logger.setLevel(logging.INFO)
    creds_handler = RotatingFileHandler(
        CREDS_LOG, maxBytes=10_000_000, backupCount=20
    )
    creds_handler.setFormatter(logging.Formatter(
        "%(asctime)s,%(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    creds_logger.addHandler(creds_handler)

    # Commands logger
    cmd_logger = logging.getLogger("CommandsLogger")
    cmd_logger.setLevel(logging.INFO)
    cmd_handler = RotatingFileHandler(
        COMMANDS_LOG, maxBytes=10_000_000, backupCount=20
    )
    cmd_handler.setFormatter(logging.Formatter(
        "%(asctime)s,%(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    cmd_logger.addHandler(cmd_handler)

    # HTTP logger
    http_logger = logging.getLogger("HTTPLogger")
    http_logger.setLevel(logging.INFO)
    http_handler = RotatingFileHandler(
        HTTP_LOG, maxBytes=10_000_000, backupCount=20
    )
    http_handler.setFormatter(logging.Formatter(
        "%(asctime)s,%(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    http_logger.addHandler(http_handler)

    # Downloads/malware URL logger
    downloads_logger = logging.getLogger("DownloadsLogger")
    downloads_logger.setLevel(logging.INFO)
    downloads_handler = RotatingFileHandler(
        DOWNLOADS_LOG, maxBytes=10_000_000, backupCount=20
    )
    downloads_handler.setFormatter(logging.Formatter(
        "%(asctime)s,%(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    downloads_logger.addHandler(downloads_handler)

    # Alerts logger
    alerts_logger = logging.getLogger("AlertsLogger")
    alerts_logger.setLevel(logging.INFO)
    alerts_handler = RotatingFileHandler(
        ALERTS_LOG, maxBytes=10_000_000, backupCount=20
    )
    alerts_handler.setFormatter(logging.Formatter(
        "%(asctime)s,%(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    alerts_logger.addHandler(alerts_handler)

    # Console logger
    console_logger = logging.getLogger("ConsoleLogger")
    console_logger.setLevel(logging.INFO)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter(
        "[%(asctime)s] %(levelname)s: %(message)s", datefmt="%H:%M:%S"
    ))
    console_logger.addHandler(console_handler)

    return creds_logger, cmd_logger, http_logger, downloads_logger, alerts_logger, console_logger


# Initialize loggers
creds_logger, cmd_logger, http_logger, downloads_logger, alerts_logger, console = setup_logging()


# =============================================================================
# ALERTING SYSTEM
# =============================================================================


class AlertManager:
    """Manages alerts and webhook notifications."""

    def __init__(self, webhook_url: str = ""):
        self.webhook_url = webhook_url
        self.alert_count = 0

    def send_alert(self, alert_type: str, data: dict):
        """Send an alert via webhook and log it."""
        self.alert_count += 1

        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "data": data
        }

        # Log the alert
        alerts_logger.info(json.dumps(alert))

        # Send webhook if configured
        if self.webhook_url:
            self._send_webhook(alert)

    def _send_webhook(self, alert: dict):
        """Send alert to webhook URL."""
        try:
            import urllib.request
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(alert).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(req, timeout=5)
            console.info(f"Alert sent to webhook: {alert['type']}")
        except Exception as e:
            console.error(f"Failed to send webhook: {e}")


# Global alert manager
alert_manager = AlertManager(WEBHOOK_URL)


# =============================================================================
# SESSION RECORDER
# =============================================================================


class SessionRecorder:
    """
    Records entire attacker sessions with keystroke timing.
    Enables forensic replay of attacks.
    """

    def __init__(self, client_ip: str, session_id: str = None):
        self.client_ip = client_ip
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.start_time = datetime.now()
        self.keystrokes = []
        self.commands = []
        self.keystroke_timings = []
        self.last_keystroke_time = None

    def record_keystroke(self, char: bytes):
        """Record a keystroke with timing information."""
        now = time.time()

        if self.last_keystroke_time:
            delay = now - self.last_keystroke_time
            self.keystroke_timings.append(delay)
        else:
            delay = 0

        self.last_keystroke_time = now

        self.keystrokes.append({
            "time": now,
            "delay": delay,
            "char": char.hex(),
            "readable": char.decode('utf-8', errors='replace')
        })

    def record_command(self, command: str):
        """Record a completed command."""
        self.commands.append({
            "time": time.time(),
            "command": command
        })

    def is_bot(self) -> tuple[bool, str]:
        """
        Analyze keystroke timing to detect if attacker is a bot or human.

        Returns: (is_bot, reason)
        """
        if len(self.keystroke_timings) < 10:
            return False, "insufficient_data"

        # Filter out very long pauses (thinking time)
        filtered_timings = [t for t in self.keystroke_timings if t < 2.0]

        if len(filtered_timings) < 5:
            return False, "insufficient_filtered_data"

        avg_delay = mean(filtered_timings)
        try:
            std_delay = stdev(filtered_timings)
        except:
            std_delay = 0

        # Bot indicators:
        # 1. Very consistent timing (low standard deviation)
        # 2. Very fast typing (< 50ms between keystrokes)
        # 3. No variation in rhythm

        if std_delay < 0.01 and avg_delay < 0.1:
            return True, "consistent_fast_timing"

        if avg_delay < 0.03:  # 30ms = inhuman speed
            return True, "superhuman_speed"

        # Check for perfectly regular intervals
        if std_delay < 0.005:
            return True, "machine_precision"

        return False, "human_like"

    def save(self):
        """Save the session recording to a JSON file."""
        is_bot, bot_reason = self.is_bot()

        session_data = {
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "start_time": self.start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
            "is_bot": is_bot,
            "bot_detection_reason": bot_reason,
            "keystroke_count": len(self.keystrokes),
            "command_count": len(self.commands),
            "commands": self.commands,
            "keystrokes": self.keystrokes,
            "timing_stats": {
                "avg_delay": mean(self.keystroke_timings) if self.keystroke_timings else 0,
                "std_delay": stdev(self.keystroke_timings) if len(self.keystroke_timings) > 1 else 0,
                "min_delay": min(self.keystroke_timings) if self.keystroke_timings else 0,
                "max_delay": max(self.keystroke_timings) if self.keystroke_timings else 0,
            }
        }

        # Save to file
        filename = SESSIONS_DIR / f"{self.session_id}_{self.client_ip}_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(session_data, f, indent=2)

        console.info(f"Session saved: {filename.name}")

        return session_data


# =============================================================================
# SSH SERVER KEY MANAGEMENT
# =============================================================================


def get_or_create_server_key():
    """Load existing RSA key or generate a new one."""
    if SERVER_KEY_PATH.exists():
        return paramiko.RSAKey(filename=str(SERVER_KEY_PATH))

    console.info(f"Generating new RSA key at {SERVER_KEY_PATH}")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(SERVER_KEY_PATH))
    return key


# =============================================================================
# SSH SERVER INTERFACE
# =============================================================================


class SSHServer(paramiko.ServerInterface):
    """SSH server interface that handles authentication and channel requests."""

    def __init__(self, client_ip, username=None, password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.expected_username = username
        self.expected_password = password
        self.authenticated_user = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        # Log the attempt
        creds_logger.info(f"{self.client_ip},{username},{password}")
        console.warning(f"Login attempt from {self.client_ip}: {username}:{password}")

        # Send alert for login attempt
        alert_manager.send_alert("login_attempt", {
            "ip": self.client_ip,
            "username": username,
            "password": password
        })

        # Check credentials if specified, otherwise accept all
        if self.expected_username and self.expected_password:
            if username == self.expected_username and password == self.expected_password:
                self.authenticated_user = username
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

        # Accept any credentials (honeypot mode)
        self.authenticated_user = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        return True


# =============================================================================
# EMULATED SHELL - ADVANCED VERSION
# =============================================================================


class EmulatedShell:
    """
    Advanced shell emulation with:
    - Session recording
    - Download trapping
    - Fake privilege escalation
    - Expanded command set
    """

    FAKE_FILES = {
        "/home/sysadmin": ["Documents", "Downloads", ".bashrc", ".bash_history", ".ssh", "notes.txt", "backup.tar.gz"],
        "/home/sysadmin/.ssh": ["authorized_keys", "id_rsa", "id_rsa.pub", "known_hosts", "config"],
        "/home/sysadmin/Documents": ["passwords.txt", "vpn-config.ovpn", "aws-keys.txt"],
        "/root": [".bashrc", ".ssh", "admin_scripts", ".mysql_history"],
        "/root/.ssh": ["authorized_keys", "id_rsa", "known_hosts"],
        "/etc": ["passwd", "shadow", "hosts", "hostname", "resolv.conf", "ssh", "mysql"],
        "/var/log": ["syslog", "auth.log", "kern.log", "messages", "secure"],
        "/var/www/html": ["index.php", "wp-config.php", "config.php", ".htaccess"],
        "/tmp": ["sess_abc123", ".X11-unix", "mysql.sock"],
    }

    FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sysadmin:x:1000:1000:System Admin:/home/sysadmin:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
admin:x:1001:1001:Admin User:/home/admin:/bin/bash"""

    FAKE_SHADOW = """root:$6$rounds=5000$saltsalt$hashed...password...:19500:0:99999:7:::
sysadmin:$6$rounds=5000$abcdefgh$anotherhash...:19500:0:99999:7:::
admin:$6$rounds=5000$xyzsalt$adminhash123...:19500:0:99999:7:::"""

    FAKE_HOSTS = """127.0.0.1       localhost
127.0.1.1       corp-server01
10.0.0.1        gateway
10.0.0.5        db-server mysql-master
10.0.0.6        db-slave mysql-slave
10.0.0.10       app-server
10.0.0.20       backup-server
192.168.1.100   jenkins ci-server"""

    FAKE_NOTES = """=== INTERNAL USE ONLY ===

Server Credentials:
- db-server: root / Db@dmin2024!
- backup-server: backup_user / B4ckup$ecure
- jenkins: admin / J3nk1ns@dm1n

AWS Access Keys (STAGING):
- Access Key: AKIAIOSFODNN7EXAMPLE
- Secret Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

VPN Config: ~/Documents/vpn-config.ovpn
MySQL root password: MyS3cur3P@ss!

TODO:
- Rotate credentials next month
- Update SSL certificates
- Check backup status on db-server
"""

    FAKE_AWS_KEYS = """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[production]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
region = us-west-2"""

    FAKE_SSH_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB9P4+OHFqXb2sPxlNH
... (truncated for security) ...
THIS IS A FAKE KEY FOR HONEYPOT PURPOSES
-----END RSA PRIVATE KEY-----"""

    FAKE_BASH_HISTORY = """cd /var/www/html
cat wp-config.php
mysql -u root -p
mysqldump -u root -p wordpress > backup.sql
ssh admin@db-server
scp backup.sql backup@backup-server:/backups/
cat /etc/shadow
sudo su -
history -c"""

    FAKE_WP_CONFIG = """<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'Wp@ssw0rd2024!');
define('DB_HOST', '10.0.0.5');
define('DB_CHARSET', 'utf8mb4');

define('AUTH_KEY',         'unique-phrase-here');
define('SECURE_AUTH_KEY',  'unique-phrase-here');

$table_prefix = 'wp_';
define('WP_DEBUG', false);
"""

    def __init__(self, channel, client_ip, session_recorder: SessionRecorder):
        self.channel = channel
        self.client_ip = client_ip
        self.recorder = session_recorder
        self.cwd = FAKE_WORKING_DIR
        self.command_count = 0
        self.start_time = datetime.now()

        # Privilege escalation state
        self.is_root = False
        self.current_user = FAKE_USERNAME

    def get_prompt(self):
        """Return the shell prompt based on privilege level."""
        if self.is_root:
            return f"root@{FAKE_HOSTNAME}:{self.cwd}# ".encode()
        return f"{self.current_user}@{FAKE_HOSTNAME}:{self.cwd}$ ".encode()

    def get_fake_ls(self, path=None, show_hidden=False):
        """Return fake directory listing."""
        target = path or self.cwd
        if target in self.FAKE_FILES:
            files = self.FAKE_FILES[target]
            if show_hidden:
                return "  ".join(files)
            return "  ".join(f for f in files if not f.startswith('.'))
        return ""

    def extract_urls(self, command: str) -> list:
        """Extract URLs from wget/curl commands."""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, command)

    def handle_download_command(self, cmd: str, base_cmd: str) -> str:
        """Handle wget/curl - trap the URLs!"""
        urls = self.extract_urls(cmd)

        for url in urls:
            # Log the malware URL
            downloads_logger.info(f"{self.client_ip},{base_cmd},{url}")
            console.critical(f"MALWARE URL CAPTURED from {self.client_ip}: {url}")

            # Send high-priority alert
            alert_manager.send_alert("malware_download_attempt", {
                "ip": self.client_ip,
                "command": base_cmd,
                "url": url,
                "full_command": cmd
            })

        if not urls:
            return f"{base_cmd}: missing URL"

        # Fake successful download
        if base_cmd == "wget":
            filename = urls[0].split('/')[-1] or "index.html"
            return f"--2024-01-15 14:32:15--  {urls[0]}\nResolving... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 1337 (1.3K)\nSaving to: '{filename}'\n\n{filename}          100%[===================>]   1.31K  --.-KB/s    in 0s\n\n2024-01-15 14:32:15 (45.2 MB/s) - '{filename}' saved [1337/1337]"
        else:  # curl
            return f"curl: (7) Failed to connect to {urls[0].split('/')[2]} port 80: Connection timed out"

    def handle_sudo(self, args: list) -> str:
        """Handle sudo commands - let them 'escalate'!"""
        if not args:
            return "usage: sudo [-u user] command"

        # Simulate password prompt
        console.critical(f"PRIVILEGE ESCALATION from {self.client_ip}: sudo {' '.join(args)}")

        alert_manager.send_alert("privilege_escalation", {
            "ip": self.client_ip,
            "command": f"sudo {' '.join(args)}"
        })

        if args[0] == "su" or (args[0] == "-i") or (args[0] == "-s"):
            # Escalate to root!
            self.is_root = True
            self.current_user = "root"
            self.cwd = "/root"
            return ""

        # Execute the command as "root"
        original_root = self.is_root
        self.is_root = True
        result = self.handle_command(' '.join(args), log_command=False)
        self.is_root = original_root

        return result if result else ""

    def handle_command(self, cmd: str, log_command: bool = True) -> Optional[str]:
        """Process a command and return the response."""
        cmd = cmd.strip()
        parts = cmd.split()

        if not parts:
            return ""

        base_cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        # Log the command
        if log_command:
            cmd_logger.info(f"{self.client_ip},{cmd}")
            self.recorder.record_command(cmd)
            self.command_count += 1

        # Command handlers
        if base_cmd in ("exit", "logout", "quit"):
            return None

        elif base_cmd == "pwd":
            return self.cwd

        elif base_cmd == "whoami":
            return "root" if self.is_root else self.current_user

        elif base_cmd == "id":
            if self.is_root:
                return "uid=0(root) gid=0(root) groups=0(root)"
            return f"uid=1000({self.current_user}) gid=1000({self.current_user}) groups=1000({self.current_user}),27(sudo),100(users)"

        elif base_cmd == "hostname":
            return FAKE_HOSTNAME

        elif base_cmd == "uname":
            if "-a" in args:
                return "Linux corp-server01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
            return "Linux"

        elif base_cmd == "uptime":
            return " 14:32:15 up 47 days,  3:22,  2 users,  load average: 0.08, 0.12, 0.09"

        elif base_cmd == "date":
            return datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")

        elif base_cmd == "ls":
            show_hidden = "-a" in args or "-la" in args or "-al" in args
            target = None
            for arg in args:
                if not arg.startswith('-'):
                    target = arg
                    break
            return self.get_fake_ls(target, show_hidden)

        elif base_cmd == "cat":
            if not args:
                return "cat: missing operand"
            return self.handle_cat(args[0])

        elif base_cmd == "cd":
            if not args or args[0] == "~":
                self.cwd = "/root" if self.is_root else FAKE_WORKING_DIR
            elif args[0] == "..":
                self.cwd = "/".join(self.cwd.rsplit("/", 1)[:-1]) or "/"
            elif args[0].startswith("/"):
                self.cwd = args[0]
            else:
                self.cwd = f"{self.cwd}/{args[0]}"
            return ""

        elif base_cmd == "df":
            return """Filesystem     1K-blocks     Used Available Use% Mounted on
/dev/sda1       51475068  8234512  40602440  17% /
tmpfs            4026172        0   4026172   0% /dev/shm
/dev/sda2      102400000  2048000 100352000   2% /home
/dev/sdb1      512000000 89234567 422765433  18% /var/www"""

        elif base_cmd == "ps":
            if "-aux" in args or "aux" in args:
                return """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168936 11572 ?        Ss   Jan01   0:15 /sbin/init
root       512  0.0  0.0  72304  5464 ?        Ss   Jan01   0:00 /usr/sbin/sshd -D
mysql      789  0.5  2.1 1256324 178456 ?      Ssl  Jan01  12:34 /usr/sbin/mysqld
www-data  1024  0.1  0.5 234567 45678 ?        S    Jan01   1:23 apache2 -k start
root      1337  0.0  0.0  12345  1234 pts/0    S+   14:32   0:00 bash"""
            return """  PID TTY          TIME CMD
    1 ?        00:00:15 systemd
  512 ?        00:00:00 sshd
 1024 pts/0    00:00:00 bash
 1337 pts/0    00:00:00 ps"""

        elif base_cmd in ("netstat", "ss"):
            return f"""Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp        0     52 10.0.0.5:22             {self.client_ip}:54321     ESTABLISHED"""

        elif base_cmd in ("wget", "curl"):
            return self.handle_download_command(cmd, base_cmd)

        elif base_cmd == "sudo":
            return self.handle_sudo(args)

        elif base_cmd == "su":
            if not args or args[0] == "-" or args[0] == "root":
                self.is_root = True
                self.current_user = "root"
                self.cwd = "/root"
                console.critical(f"ROOT ESCALATION from {self.client_ip}: su")
                alert_manager.send_alert("privilege_escalation", {
                    "ip": self.client_ip,
                    "command": "su"
                })
                return ""
            return f"su: user {args[0]} does not exist"

        elif base_cmd == "history":
            return self.FAKE_BASH_HISTORY

        elif base_cmd == "env":
            user = "root" if self.is_root else self.current_user
            home = "/root" if self.is_root else FAKE_WORKING_DIR
            return f"""USER={user}
HOME={home}
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
TERM=xterm-256color
LANG=en_US.UTF-8
PWD={self.cwd}
MYSQL_PWD=MyS3cur3P@ss!"""

        elif base_cmd == "ifconfig" or base_cmd == "ip":
            return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255
        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>
        ether 00:16:3e:xx:xx:xx  txqueuelen 1000  (Ethernet)
        RX packets 123456  bytes 12345678 (12.3 MB)
        TX packets 654321  bytes 87654321 (87.6 MB)"""

        elif base_cmd == "mysql":
            return "ERROR 1045 (28000): Access denied for user (using password: NO)"

        elif base_cmd == "help":
            return "GNU bash, version 5.1.16. Type 'help' for more information."

        elif base_cmd == "echo":
            return ' '.join(args)

        elif base_cmd == "rm":
            return ""  # Pretend it worked

        elif base_cmd == "chmod" or base_cmd == "chown":
            return ""  # Pretend it worked

        elif base_cmd == "mkdir":
            return ""  # Pretend it worked

        elif base_cmd == "touch":
            return ""  # Pretend it worked

        elif base_cmd == "cp" or base_cmd == "mv":
            return ""  # Pretend it worked

        elif base_cmd == "which":
            if args:
                common_commands = ["ls", "cat", "grep", "find", "wget", "curl", "python", "python3", "bash", "sh"]
                if args[0] in common_commands:
                    return f"/usr/bin/{args[0]}"
            return ""

        else:
            return f"{base_cmd}: command not found"

    def handle_cat(self, filepath: str) -> str:
        """Handle cat command with expanded file content."""
        # Remove leading ./ if present
        if filepath.startswith("./"):
            filepath = filepath[2:]

        # Handle relative paths
        if not filepath.startswith("/"):
            full_path = f"{self.cwd}/{filepath}"
        else:
            full_path = filepath

        # File content mapping
        file_contents = {
            "/etc/passwd": self.FAKE_PASSWD,
            "/etc/shadow": self.FAKE_SHADOW if self.is_root else "cat: /etc/shadow: Permission denied",
            "/etc/hosts": self.FAKE_HOSTS,
            "/home/sysadmin/notes.txt": self.FAKE_NOTES,
            "/home/sysadmin/.bashrc": "# .bashrc\nexport PATH=$PATH:/usr/local/bin\nalias ll='ls -la'\nalias mysql='mysql -u root -p'",
            "/home/sysadmin/.bash_history": self.FAKE_BASH_HISTORY,
            "/home/sysadmin/Documents/aws-keys.txt": self.FAKE_AWS_KEYS,
            "/home/sysadmin/.ssh/id_rsa": self.FAKE_SSH_PRIVATE_KEY if self.is_root else "cat: /home/sysadmin/.ssh/id_rsa: Permission denied",
            "/var/www/html/wp-config.php": self.FAKE_WP_CONFIG,
            "/root/.bash_history": self.FAKE_BASH_HISTORY if self.is_root else "cat: /root/.bash_history: Permission denied",
        }

        # Check for exact match
        if full_path in file_contents:
            content = file_contents[full_path]
            # Log sensitive file access
            if any(x in full_path for x in ["shadow", "id_rsa", "aws", "password", "wp-config"]):
                alert_manager.send_alert("sensitive_file_access", {
                    "ip": self.client_ip,
                    "file": full_path,
                    "is_root": self.is_root
                })
            return content

        # Check partial matches (for relative paths)
        for path, content in file_contents.items():
            if filepath == path.split("/")[-1]:
                return content

        return f"cat: {filepath}: No such file or directory"

    def run(self):
        """Main shell loop with session recording."""
        # Send welcome banner
        self.channel.send(b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
        self.channel.send(b" * Documentation:  https://help.ubuntu.com\r\n")
        self.channel.send(b" * Management:     https://landscape.canonical.com\r\n")
        self.channel.send(b" * Support:        https://ubuntu.com/advantage\r\n\r\n")
        self.channel.send(b"Last login: " + datetime.now().strftime("%a %b %d %H:%M:%S %Y").encode() + b" from " + self.client_ip.encode() + b"\r\n")
        self.channel.send(self.get_prompt())

        command = b""

        while True:
            try:
                char = self.channel.recv(1)

                if not char:
                    break

                # Record keystroke
                self.recorder.record_keystroke(char)

                # Echo character back
                self.channel.send(char)

                # Handle special characters
                if char == b"\r" or char == b"\n":
                    cmd_str = command.decode("utf-8", errors="ignore").strip()

                    if cmd_str:
                        response = self.handle_command(cmd_str)

                        if response is None:
                            # Exit command
                            self.channel.send(b"\r\nlogout\r\n")
                            console.info(
                                f"Session ended for {self.client_ip} "
                                f"(commands: {self.command_count})"
                            )
                            break

                        if response:
                            self.channel.send(b"\r\n" + response.encode() + b"\r\n")
                        else:
                            self.channel.send(b"\r\n")
                    else:
                        self.channel.send(b"\r\n")

                    self.channel.send(self.get_prompt())
                    command = b""

                elif char == b"\x7f" or char == b"\x08":
                    # Backspace
                    if command:
                        command = command[:-1]
                        self.channel.send(b"\b \b")

                elif char == b"\x03":
                    # Ctrl+C
                    self.channel.send(b"^C\r\n")
                    self.channel.send(self.get_prompt())
                    command = b""

                elif char == b"\x04":
                    # Ctrl+D (EOF)
                    self.channel.send(b"\r\nlogout\r\n")
                    break

                else:
                    command += char

            except Exception as e:
                console.error(f"Shell error for {self.client_ip}: {e}")
                break


# =============================================================================
# CLIENT HANDLER
# =============================================================================


def handle_client(client_socket, addr, username=None, password=None, tarpit=False):
    """Handle an individual SSH client connection."""
    client_ip = addr[0]
    console.info(f"New connection from {client_ip}")

    # Create session recorder
    session_recorder = SessionRecorder(client_ip)

    # Send connection alert
    alert_manager.send_alert("new_connection", {
        "ip": client_ip,
        "session_id": session_recorder.session_id
    })

    try:
        # Set up transport
        transport = paramiko.Transport(client_socket)
        transport.local_version = SSH_BANNER

        # Load server key
        host_key = get_or_create_server_key()
        transport.add_server_key(host_key)

        # Start SSH server
        server = SSHServer(client_ip, username, password)
        transport.start_server(server=server)

        # Wait for channel
        channel = transport.accept(100)

        if channel is None:
            console.warning(f"No channel opened for {client_ip}")
            return

        # Tarpit mode
        if tarpit:
            console.info(f"Tarpit mode active for {client_ip}")
            banner = "Welcome to Ubuntu 22.04 LTS\r\n" * 50
            for char in banner:
                channel.send(char.encode())
                time.sleep(5)

        # Run emulated shell
        shell = EmulatedShell(channel, client_ip, session_recorder)
        shell.run()

    except paramiko.SSHException as e:
        console.warning(f"SSH error for {client_ip}: {e}")
    except Exception as e:
        console.error(f"Error handling {client_ip}: {e}")
    finally:
        # Save session recording
        session_data = session_recorder.save()

        # Send session summary alert
        alert_manager.send_alert("session_ended", {
            "ip": client_ip,
            "session_id": session_recorder.session_id,
            "duration": session_data["duration_seconds"],
            "command_count": session_data["command_count"],
            "is_bot": session_data["is_bot"],
            "bot_reason": session_data["bot_detection_reason"]
        })

        # Log bot detection
        if session_data["is_bot"]:
            console.warning(f"BOT DETECTED from {client_ip}: {session_data['bot_detection_reason']}")

        try:
            transport.close()
        except:
            pass
        client_socket.close()
        console.info(f"Connection closed for {client_ip}")


# =============================================================================
# SSH HONEYPOT SERVER
# =============================================================================


def run_ssh_honeypot(address, port, username=None, password=None, tarpit=False):
    """Start the SSH honeypot server."""
    console.info(f"Starting SSH honeypot on {address}:{port}")

    if tarpit:
        console.info("Tarpit mode ENABLED - connections will be slowed")

    if username and password:
        console.info(f"Credentials required: {username}:{'*' * len(password)}")
    else:
        console.info("Accepting ALL credentials (honeypot mode)")

    console.info(f"Session recordings: {SESSIONS_DIR}")
    console.info(f"Malware URLs logged to: {DOWNLOADS_LOG}")

    if WEBHOOK_URL:
        console.info(f"Webhook alerts enabled")

    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((address, port))
        server_socket.listen(100)
        console.info(f"SSH honeypot listening on {address}:{port}")

        while True:
            try:
                client_socket, addr = server_socket.accept()

                thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, addr, username, password, tarpit)
                )
                thread.daemon = True
                thread.start()

            except Exception as e:
                console.error(f"Error accepting connection: {e}")

    except KeyboardInterrupt:
        console.info("Shutting down SSH honeypot...")
    finally:
        server_socket.close()


# =============================================================================
# HTTP HONEYPOT
# =============================================================================


def run_http_honeypot(address, port, username="admin", password="admin"):
    """Start the HTTP WordPress honeypot."""
    try:
        from flask import Flask, render_template_string, request
    except ImportError:
        console.error("Flask not installed. Run: pip install flask")
        return

    app = Flask(__name__)

    import logging as flask_logging
    flask_logging.getLogger("werkzeug").setLevel(flask_logging.ERROR)

    WP_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log In &lsaquo; WordPress</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f1f1; margin: 0; padding: 0; }
        .login { width: 320px; margin: 100px auto; padding: 20px; }
        .login h1 { text-align: center; margin-bottom: 25px; }
        .login h1 a { background-image: url('https://s.w.org/style/images/wp-logo-blue.png'); background-size: 84px; width: 84px; height: 84px; display: block; margin: 0 auto; text-indent: -9999px; }
        .login-form { background: #fff; border: 1px solid #c3c4c7; box-shadow: 0 1px 3px rgba(0,0,0,.04); padding: 26px 24px; }
        .login-form label { display: block; margin-bottom: 3px; font-size: 14px; }
        .login-form input[type="text"], .login-form input[type="password"] { width: 100%; padding: 5px 10px; margin-bottom: 16px; font-size: 24px; box-sizing: border-box; border: 1px solid #8c8f94; border-radius: 4px; }
        .login-form input[type="submit"] { background: #2271b1; border: 1px solid #2271b1; color: #fff; padding: 6px 12px; font-size: 13px; border-radius: 3px; cursor: pointer; width: 100%; }
        .login-form input[type="submit"]:hover { background: #135e96; }
        .error { background: #d63638; color: #fff; padding: 12px; margin-bottom: 16px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="login">
        <h1><a href="#">WordPress</a></h1>
        <div class="login-form">
            {% if error %}<div class="error">{{ error }}</div>{% endif %}
            <form method="post" action="/wp-login.php">
                <label for="user_login">Username or Email Address</label>
                <input type="text" name="log" id="user_login" required>
                <label for="user_pass">Password</label>
                <input type="password" name="pwd" id="user_pass" required>
                <input type="submit" value="Log In">
            </form>
        </div>
    </div>
</body>
</html>
"""

    @app.route("/")
    @app.route("/wp-login.php", methods=["GET"])
    @app.route("/wp-admin", methods=["GET"])
    @app.route("/wp-admin/", methods=["GET"])
    def login_page():
        return render_template_string(WP_LOGIN_TEMPLATE, error=None)

    @app.route("/wp-login.php", methods=["POST"])
    def handle_login():
        user = request.form.get("log", "")
        pwd = request.form.get("pwd", "")
        ip = request.remote_addr

        http_logger.info(f"{ip},{user},{pwd}")
        console.warning(f"HTTP login attempt from {ip}: {user}:{pwd}")

        alert_manager.send_alert("http_login_attempt", {
            "ip": ip,
            "username": user,
            "password": pwd
        })

        if user == username and pwd == password:
            return "Redirecting to dashboard...", 302

        return render_template_string(WP_LOGIN_TEMPLATE, error="Invalid username or password.")

    console.info(f"Starting HTTP honeypot on {address}:{port}")
    app.run(host=address, port=port, debug=False, threaded=True)


# =============================================================================
# ANALYTICS DASHBOARD
# =============================================================================


def run_dashboard(port=8050):
    """Start the analytics dashboard."""
    try:
        from dash import Dash, html, dcc, dash_table
        import dash_bootstrap_components as dbc
        import plotly.express as px
        import pandas as pd
    except ImportError:
        console.error("Dashboard dependencies not installed. Run: pip install dash dash-bootstrap-components plotly pandas")
        return

    app = Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])
    app.title = "Honeypot Dashboard"

    def load_credentials():
        """Load credential attempts from log file."""
        data = []
        if CREDS_LOG.exists():
            with open(CREDS_LOG, 'r') as f:
                for line in f:
                    try:
                        parts = line.strip().split(',', 3)
                        if len(parts) >= 4:
                            data.append({
                                'timestamp': parts[0],
                                'ip': parts[1],
                                'username': parts[2],
                                'password': parts[3]
                            })
                    except:
                        pass
        return pd.DataFrame(data) if data else pd.DataFrame(columns=['timestamp', 'ip', 'username', 'password'])

    def load_commands():
        """Load commands from log file."""
        data = []
        if COMMANDS_LOG.exists():
            with open(COMMANDS_LOG, 'r') as f:
                for line in f:
                    try:
                        parts = line.strip().split(',', 2)
                        if len(parts) >= 3:
                            data.append({
                                'timestamp': parts[0],
                                'ip': parts[1],
                                'command': parts[2]
                            })
                    except:
                        pass
        return pd.DataFrame(data) if data else pd.DataFrame(columns=['timestamp', 'ip', 'command'])

    def load_sessions():
        """Load session recordings."""
        sessions = []
        for session_file in SESSIONS_DIR.glob("*.json"):
            try:
                with open(session_file, 'r') as f:
                    sessions.append(json.load(f))
            except:
                pass
        return sessions

    def create_layout():
        creds_df = load_credentials()
        cmds_df = load_commands()
        sessions = load_sessions()

        # Calculate stats
        total_logins = len(creds_df)
        unique_ips = creds_df['ip'].nunique() if not creds_df.empty else 0
        total_commands = len(cmds_df)
        bot_count = sum(1 for s in sessions if s.get('is_bot', False))

        # Top passwords
        top_passwords = creds_df['password'].value_counts().head(10) if not creds_df.empty else pd.Series()
        top_usernames = creds_df['username'].value_counts().head(10) if not creds_df.empty else pd.Series()
        top_ips = creds_df['ip'].value_counts().head(10) if not creds_df.empty else pd.Series()
        top_commands = cmds_df['command'].value_counts().head(10) if not cmds_df.empty else pd.Series()

        return dbc.Container([
            html.H1("Honeypot Analytics", className="text-center my-4"),

            # Stats cards
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardBody([
                        html.H4("Total Login Attempts", className="card-title"),
                        html.H2(str(total_logins), className="text-primary")
                    ])
                ]), width=3),
                dbc.Col(dbc.Card([
                    dbc.CardBody([
                        html.H4("Unique IPs", className="card-title"),
                        html.H2(str(unique_ips), className="text-info")
                    ])
                ]), width=3),
                dbc.Col(dbc.Card([
                    dbc.CardBody([
                        html.H4("Commands Executed", className="card-title"),
                        html.H2(str(total_commands), className="text-warning")
                    ])
                ]), width=3),
                dbc.Col(dbc.Card([
                    dbc.CardBody([
                        html.H4("Bots Detected", className="card-title"),
                        html.H2(str(bot_count), className="text-danger")
                    ])
                ]), width=3),
            ], className="mb-4"),

            # Charts
            dbc.Row([
                dbc.Col([
                    html.H4("Top 10 Passwords"),
                    dcc.Graph(
                        figure=px.bar(
                            x=top_passwords.values,
                            y=top_passwords.index,
                            orientation='h',
                            template='plotly_dark'
                        ) if not top_passwords.empty else {}
                    )
                ], width=6),
                dbc.Col([
                    html.H4("Top 10 Usernames"),
                    dcc.Graph(
                        figure=px.bar(
                            x=top_usernames.values,
                            y=top_usernames.index,
                            orientation='h',
                            template='plotly_dark'
                        ) if not top_usernames.empty else {}
                    )
                ], width=6),
            ], className="mb-4"),

            dbc.Row([
                dbc.Col([
                    html.H4("Top 10 Attacking IPs"),
                    dcc.Graph(
                        figure=px.bar(
                            x=top_ips.values,
                            y=top_ips.index,
                            orientation='h',
                            template='plotly_dark'
                        ) if not top_ips.empty else {}
                    )
                ], width=6),
                dbc.Col([
                    html.H4("Top 10 Commands"),
                    dcc.Graph(
                        figure=px.bar(
                            x=top_commands.values,
                            y=top_commands.index,
                            orientation='h',
                            template='plotly_dark'
                        ) if not top_commands.empty else {}
                    )
                ], width=6),
            ], className="mb-4"),

            # Recent activity table
            html.H4("Recent Login Attempts"),
            dash_table.DataTable(
                data=creds_df.tail(20).to_dict('records') if not creds_df.empty else [],
                columns=[{'name': col, 'id': col} for col in ['timestamp', 'ip', 'username', 'password']],
                style_table={'overflowX': 'auto'},
                style_cell={'textAlign': 'left', 'backgroundColor': '#303030', 'color': 'white'},
                style_header={'backgroundColor': '#404040', 'fontWeight': 'bold'},
                page_size=10
            ),

            # Refresh interval
            dcc.Interval(id='interval', interval=30000, n_intervals=0)
        ], fluid=True)

    app.layout = create_layout

    console.info(f"Starting analytics dashboard on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Advanced SSH/HTTP Honeypot with analytics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --ssh -p 2222                    # Basic SSH honeypot
  %(prog)s --ssh -p 22 --tarpit             # SSH with tarpit mode
  %(prog)s --http -p 8080                   # HTTP WordPress honeypot
  %(prog)s --dashboard                       # Analytics dashboard only
  %(prog)s --ssh -p 2222 --webhook URL      # SSH with webhook alerts

Environment Variables:
  HONEYPOT_WEBHOOK_URL   Webhook URL for alerts (Discord, Slack, etc.)
        """
    )

    parser.add_argument("-a", "--address", type=str, default="0.0.0.0", help="Bind address")
    parser.add_argument("-p", "--port", type=int, help="Port to listen on")
    parser.add_argument("-u", "--username", type=str, help="Expected username")
    parser.add_argument("-w", "--password", type=str, help="Expected password")
    parser.add_argument("--ssh", action="store_true", help="Run SSH honeypot")
    parser.add_argument("--http", action="store_true", help="Run HTTP honeypot")
    parser.add_argument("--dashboard", action="store_true", help="Run analytics dashboard")
    parser.add_argument("--tarpit", action="store_true", help="Enable tarpit mode (SSH)")
    parser.add_argument("--webhook", type=str, help="Webhook URL for alerts")

    args = parser.parse_args()

    # Set webhook URL
    if args.webhook:
        global alert_manager
        alert_manager = AlertManager(args.webhook)

    mode_count = sum([args.ssh, args.http, args.dashboard])

    if mode_count == 0:
        parser.error("Must specify --ssh, --http, or --dashboard")

    if mode_count > 1:
        parser.error("Cannot run multiple modes simultaneously (use separate processes)")

    if (args.ssh or args.http) and not args.port:
        parser.error("--port is required for --ssh and --http modes")

    try:
        if args.ssh:
            run_ssh_honeypot(args.address, args.port, args.username, args.password, args.tarpit)
        elif args.http:
            run_http_honeypot(args.address, args.port, args.username or "admin", args.password or "admin")
        elif args.dashboard:
            run_dashboard(args.port or 8050)
    except PermissionError:
        console.error(f"Permission denied for port {args.port}. Try sudo or use port > 1024")
    except KeyboardInterrupt:
        console.info("Honeypot stopped.")


if __name__ == "__main__":
    main()
