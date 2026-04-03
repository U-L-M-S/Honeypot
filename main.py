#!/usr/bin/env python3
"""
SSH Honeypot - A security research tool for capturing and analyzing SSH attack patterns.

Features:
- SSH honeypot with realistic shell emulation
- HTTP/WordPress login honeypot
- Tarpit mode to slow down attackers
- Comprehensive logging with rotation
- Analytics dashboard
"""

import argparse
import logging
import os
import socket
import sys
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

import paramiko

# =============================================================================
# CONFIGURATION
# =============================================================================

# Directory setup
BASE_DIR = Path(__file__).parent
LOG_DIR = BASE_DIR / "logs"
STATIC_DIR = BASE_DIR / "static"

# Create directories if they don't exist
LOG_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

# Log file paths
CREDS_LOG = LOG_DIR / "credentials.log"
COMMANDS_LOG = LOG_DIR / "commands.log"
HTTP_LOG = LOG_DIR / "http_attempts.log"

# SSH Configuration
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
SERVER_KEY_PATH = STATIC_DIR / "server.key"

# Fake system configuration
FAKE_HOSTNAME = "corp-server01"
FAKE_USERNAME = "sysadmin"
FAKE_WORKING_DIR = "/home/sysadmin"

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

    # Credentials logger - captures login attempts
    creds_logger = logging.getLogger("CredentialsLogger")
    creds_logger.setLevel(logging.INFO)
    creds_handler = RotatingFileHandler(
        CREDS_LOG, maxBytes=1_000_000, backupCount=10
    )
    creds_handler.setFormatter(logging.Formatter(
        "%(asctime)s,%(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    creds_logger.addHandler(creds_handler)

    # Commands logger - captures executed commands
    cmd_logger = logging.getLogger("CommandsLogger")
    cmd_logger.setLevel(logging.INFO)
    cmd_handler = RotatingFileHandler(
        COMMANDS_LOG, maxBytes=1_000_000, backupCount=10
    )
    cmd_handler.setFormatter(logging.Formatter(
        "%(asctime)s,%(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    cmd_logger.addHandler(cmd_handler)

    # HTTP logger - captures web login attempts
    http_logger = logging.getLogger("HTTPLogger")
    http_logger.setLevel(logging.INFO)
    http_handler = RotatingFileHandler(
        HTTP_LOG, maxBytes=1_000_000, backupCount=10
    )
    http_handler.setFormatter(logging.Formatter(
        "%(asctime)s,%(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    http_logger.addHandler(http_handler)

    # Console logger for operator
    console_logger = logging.getLogger("ConsoleLogger")
    console_logger.setLevel(logging.INFO)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter(
        "[%(asctime)s] %(levelname)s: %(message)s", datefmt="%H:%M:%S"
    ))
    console_logger.addHandler(console_handler)

    return creds_logger, cmd_logger, http_logger, console_logger


# Initialize loggers
creds_logger, cmd_logger, http_logger, console = setup_logging()

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
        console.warning(
            f"Login attempt from {self.client_ip}: {username}:{password}"
        )

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
# EMULATED SHELL - IMPROVED VERSION
# =============================================================================


class EmulatedShell:
    """
    Realistic shell emulation with expanded command support.

    Improvements over original:
    - More commands (id, uname, hostname, uptime, date, df, ps, netstat, etc.)
    - Realistic fake filesystem
    - Command history tracking
    - Session statistics
    """

    FAKE_FILES = {
        "/home/sysadmin": ["Documents", "Downloads", ".bashrc", ".ssh", "notes.txt"],
        "/home/sysadmin/.ssh": ["authorized_keys", "id_rsa", "id_rsa.pub", "known_hosts"],
        "/etc": ["passwd", "shadow", "hosts", "hostname", "resolv.conf"],
        "/var/log": ["syslog", "auth.log", "kern.log", "messages"],
        "/tmp": ["sess_abc123", ".X11-unix"],
    }

    FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sysadmin:x:1000:1000:System Admin:/home/sysadmin:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false"""

    FAKE_SHADOW = """root:$6$xyz...REDACTED...:19500:0:99999:7:::
sysadmin:$6$abc...REDACTED...:19500:0:99999:7:::"""

    FAKE_HOSTS = """127.0.0.1       localhost
127.0.1.1       corp-server01
10.0.0.1        gateway
10.0.0.5        db-server
10.0.0.10       app-server"""

    FAKE_NOTES = """TODO:
- Update SSL certificates (expires next month)
- Check backup status on db-server
- Review firewall rules
- Password for staging: St@ging2024!
"""

    def __init__(self, channel, client_ip):
        self.channel = channel
        self.client_ip = client_ip
        self.cwd = FAKE_WORKING_DIR
        self.command_count = 0
        self.start_time = datetime.now()

    def get_prompt(self):
        return f"{FAKE_USERNAME}@{FAKE_HOSTNAME}:{self.cwd}$ ".encode()

    def get_fake_ls(self, path=None):
        """Return fake directory listing."""
        target = path or self.cwd
        if target in self.FAKE_FILES:
            return "  ".join(self.FAKE_FILES[target])
        return ""

    def handle_command(self, cmd):
        """Process a command and return the response."""
        cmd = cmd.strip()
        parts = cmd.split()

        if not parts:
            return ""

        base_cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        # Log the command
        cmd_logger.info(f"{self.client_ip},{cmd}")
        self.command_count += 1

        # Command handlers
        if base_cmd == "exit" or base_cmd == "logout" or base_cmd == "quit":
            return None  # Signal to close connection

        elif base_cmd == "pwd":
            return self.cwd

        elif base_cmd == "whoami":
            return FAKE_USERNAME

        elif base_cmd == "id":
            return f"uid=1000({FAKE_USERNAME}) gid=1000({FAKE_USERNAME}) groups=1000({FAKE_USERNAME}),27(sudo),100(users)"

        elif base_cmd == "hostname":
            return FAKE_HOSTNAME

        elif base_cmd == "uname":
            if "-a" in args:
                return "Linux corp-server01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
            return "Linux"

        elif base_cmd == "uptime":
            return " 14:32:15 up 47 days,  3:22,  2 users,  load average: 0.08, 0.12, 0.09"

        elif base_cmd == "date":
            return datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")

        elif base_cmd == "ls":
            target = args[0] if args and not args[0].startswith("-") else self.cwd
            return self.get_fake_ls(target)

        elif base_cmd == "cat":
            if not args:
                return "cat: missing operand"

            filepath = args[0]
            if filepath == "/etc/passwd" or filepath == "passwd":
                return self.FAKE_PASSWD
            elif filepath == "/etc/shadow" or filepath == "shadow":
                return "cat: /etc/shadow: Permission denied"
            elif filepath == "/etc/hosts" or filepath == "hosts":
                return self.FAKE_HOSTS
            elif filepath == "notes.txt" or filepath == "/home/sysadmin/notes.txt":
                return self.FAKE_NOTES
            elif filepath == ".bashrc" or filepath == "/home/sysadmin/.bashrc":
                return "# .bashrc\nexport PATH=$PATH:/usr/local/bin\nalias ll='ls -la'"
            else:
                return f"cat: {filepath}: No such file or directory"

        elif base_cmd == "cd":
            if not args or args[0] == "~":
                self.cwd = FAKE_WORKING_DIR
            elif args[0] == "..":
                self.cwd = "/".join(self.cwd.rsplit("/", 1)[:-1]) or "/"
            elif args[0].startswith("/"):
                self.cwd = args[0]
            else:
                self.cwd = f"{self.cwd}/{args[0]}"
            return ""

        elif base_cmd == "df":
            return """Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/sda1       51475068 8234512  40602440  17% /
tmpfs            4026172       0   4026172   0% /dev/shm
/dev/sda2      102400000 2048000 100352000   2% /home"""

        elif base_cmd == "ps":
            return """  PID TTY          TIME CMD
    1 ?        00:00:02 systemd
  512 ?        00:00:00 sshd
 1024 pts/0    00:00:00 bash
 1025 pts/0    00:00:00 ps"""

        elif base_cmd == "netstat" or base_cmd == "ss":
            return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp        0     52 10.0.0.5:22             """ + self.client_ip + """:54321     ESTABLISHED"""

        elif base_cmd == "wget" or base_cmd == "curl":
            return f"{base_cmd}: command not found (blocked by firewall policy)"

        elif base_cmd == "sudo":
            return f"[sudo] password for {FAKE_USERNAME}: \nSorry, try again."

        elif base_cmd == "history":
            return """    1  ssh db-server
    2  ls -la
    3  cat /etc/passwd
    4  df -h
    5  history"""

        elif base_cmd == "env":
            return f"""USER={FAKE_USERNAME}
HOME={FAKE_WORKING_DIR}
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
TERM=xterm-256color
LANG=en_US.UTF-8"""

        elif base_cmd == "help":
            return "Available commands: ls, cd, pwd, cat, whoami, id, hostname, uname, date, uptime, df, ps, netstat, env, history, exit"

        else:
            return f"{base_cmd}: command not found"

    def run(self):
        """Main shell loop."""
        self.channel.send(b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
        self.channel.send(b" * Documentation:  https://help.ubuntu.com\r\n")
        self.channel.send(b" * Management:     https://landscape.canonical.com\r\n")
        self.channel.send(b" * Support:        https://ubuntu.com/advantage\r\n\r\n")
        self.channel.send(f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {self.client_ip}\r\n".encode())
        self.channel.send(self.get_prompt())

        command = b""

        while True:
            try:
                char = self.channel.recv(1)

                if not char:
                    break

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

        # Tarpit mode - send banner very slowly to waste attacker's time
        if tarpit:
            console.info(f"Tarpit mode active for {client_ip}")
            banner = "Welcome to Ubuntu 22.04 LTS\r\n" * 50
            for char in banner:
                channel.send(char.encode())
                time.sleep(5)

        # Run emulated shell
        shell = EmulatedShell(channel, client_ip)
        shell.run()

    except paramiko.SSHException as e:
        console.warning(f"SSH error for {client_ip}: {e}")
    except Exception as e:
        console.error(f"Error handling {client_ip}: {e}")
    finally:
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

                # Handle each client in a separate thread
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
# HTTP HONEYPOT (WordPress Login)
# =============================================================================


def run_http_honeypot(address, port, username="admin", password="admin"):
    """Start the HTTP WordPress honeypot."""
    try:
        from flask import Flask, render_template_string, request
    except ImportError:
        console.error("Flask not installed. Run: pip install flask")
        return

    app = Flask(__name__)

    # Disable Flask's default logging
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
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f1f1f1;
            margin: 0;
            padding: 0;
        }
        .login {
            width: 320px;
            margin: 100px auto;
            padding: 20px;
        }
        .login h1 {
            text-align: center;
            margin-bottom: 25px;
        }
        .login h1 a {
            background-image: url('https://s.w.org/style/images/wp-logo-blue.png');
            background-size: 84px;
            width: 84px;
            height: 84px;
            display: block;
            margin: 0 auto;
            text-indent: -9999px;
        }
        .login-form {
            background: #fff;
            border: 1px solid #c3c4c7;
            box-shadow: 0 1px 3px rgba(0,0,0,.04);
            padding: 26px 24px;
        }
        .login-form label {
            display: block;
            margin-bottom: 3px;
            font-size: 14px;
        }
        .login-form input[type="text"],
        .login-form input[type="password"] {
            width: 100%;
            padding: 5px 10px;
            margin-bottom: 16px;
            font-size: 24px;
            box-sizing: border-box;
            border: 1px solid #8c8f94;
            border-radius: 4px;
        }
        .login-form input[type="submit"] {
            background: #2271b1;
            border: 1px solid #2271b1;
            color: #fff;
            padding: 6px 12px;
            font-size: 13px;
            border-radius: 3px;
            cursor: pointer;
            width: 100%;
        }
        .login-form input[type="submit"]:hover {
            background: #135e96;
        }
        .error {
            background: #d63638;
            color: #fff;
            padding: 12px;
            margin-bottom: 16px;
            border-radius: 4px;
        }
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

        # Log the attempt
        http_logger.info(f"{ip},{user},{pwd}")
        console.warning(f"HTTP login attempt from {ip}: {user}:{pwd}")

        if user == username and pwd == password:
            return "Redirecting to dashboard...", 302

        return render_template_string(
            WP_LOGIN_TEMPLATE,
            error="Invalid username or password."
        )

    console.info(f"Starting HTTP honeypot on {address}:{port}")
    console.info(f"Valid credentials: {username}:{'*' * len(password)}")

    app.run(host=address, port=port, debug=False, threaded=True)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="SSH/HTTP Honeypot - Security research tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --ssh -a 0.0.0.0 -p 2222
  %(prog)s --ssh -a 0.0.0.0 -p 22 -u admin -w password --tarpit
  %(prog)s --http -a 0.0.0.0 -p 8080
        """
    )

    parser.add_argument(
        "-a", "--address",
        type=str,
        default="0.0.0.0",
        help="Bind address (default: 0.0.0.0)"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        required=True,
        help="Port to listen on"
    )
    parser.add_argument(
        "-u", "--username",
        type=str,
        help="Expected username (accepts all if not set)"
    )
    parser.add_argument(
        "-w", "--password",
        type=str,
        help="Expected password (accepts all if not set)"
    )
    parser.add_argument(
        "--ssh",
        action="store_true",
        help="Run SSH honeypot"
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="Run HTTP/WordPress honeypot"
    )
    parser.add_argument(
        "--tarpit",
        action="store_true",
        help="Enable tarpit mode (SSH only) - slows down attackers"
    )

    args = parser.parse_args()

    if not args.ssh and not args.http:
        parser.error("Must specify either --ssh or --http")

    if args.ssh and args.http:
        parser.error("Cannot run both --ssh and --http simultaneously")

    try:
        if args.ssh:
            run_ssh_honeypot(
                args.address,
                args.port,
                args.username,
                args.password,
                args.tarpit
            )
        elif args.http:
            run_http_honeypot(
                args.address,
                args.port,
                args.username or "admin",
                args.password or "admin"
            )
    except PermissionError:
        console.error(f"Permission denied for port {args.port}. Try sudo or use port > 1024")
    except KeyboardInterrupt:
        console.info("Honeypot stopped.")


if __name__ == "__main__":
    main()
