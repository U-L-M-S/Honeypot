"""
Tests for SSHServer class - SSH authentication handling.
"""

from unittest.mock import patch, MagicMock

import pytest
import paramiko

import main
from main import SSHServer


class TestSSHServerInit:
    """Tests for SSHServer initialization."""

    def test_init_stores_client_ip(self):
        """SSHServer should store client IP."""
        server = SSHServer("192.168.1.100")
        assert server.client_ip == "192.168.1.100"

    def test_init_no_credentials(self):
        """SSHServer should work without expected credentials."""
        server = SSHServer("10.0.0.1")
        assert server.expected_username is None
        assert server.expected_password is None

    def test_init_with_credentials(self):
        """SSHServer should store expected credentials."""
        server = SSHServer("10.0.0.1", username="admin", password="secret")
        assert server.expected_username == "admin"
        assert server.expected_password == "secret"

    def test_init_authenticated_user_none(self):
        """Authenticated user should be None initially."""
        server = SSHServer("10.0.0.1")
        assert server.authenticated_user is None

    def test_init_event_created(self):
        """Threading event should be created."""
        server = SSHServer("10.0.0.1")
        assert server.event is not None


class TestChannelRequest:
    """Tests for channel request handling."""

    def test_session_channel_allowed(self):
        """Session channel should be allowed."""
        server = SSHServer("10.0.0.1")
        result = server.check_channel_request("session", 1)
        assert result == paramiko.OPEN_SUCCEEDED

    def test_other_channel_denied(self):
        """Non-session channels should be denied."""
        server = SSHServer("10.0.0.1")

        result = server.check_channel_request("x11", 1)
        assert result == paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        result = server.check_channel_request("forwarded-tcpip", 1)
        assert result == paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class TestAllowedAuths:
    """Tests for authentication methods."""

    def test_password_auth_allowed(self):
        """Password authentication should be allowed."""
        server = SSHServer("10.0.0.1")
        result = server.get_allowed_auths("anyuser")
        assert result == "password"


class TestPasswordAuthentication:
    """Tests for password authentication."""

    def test_auth_no_credentials_accepts_all(self):
        """Without expected credentials, any login should succeed."""
        server = SSHServer("10.0.0.1")

        with patch.object(main.creds_logger, 'info'):
            with patch.object(main.alert_manager, 'send_alert'):
                result = server.check_auth_password("anyuser", "anypass")

        assert result == paramiko.AUTH_SUCCESSFUL
        assert server.authenticated_user == "anyuser"

    def test_auth_correct_credentials(self):
        """Correct credentials should succeed."""
        server = SSHServer("10.0.0.1", username="admin", password="secret123")

        with patch.object(main.creds_logger, 'info'):
            with patch.object(main.alert_manager, 'send_alert'):
                result = server.check_auth_password("admin", "secret123")

        assert result == paramiko.AUTH_SUCCESSFUL
        assert server.authenticated_user == "admin"

    def test_auth_wrong_username(self):
        """Wrong username should fail."""
        server = SSHServer("10.0.0.1", username="admin", password="secret123")

        with patch.object(main.creds_logger, 'info'):
            with patch.object(main.alert_manager, 'send_alert'):
                result = server.check_auth_password("wronguser", "secret123")

        assert result == paramiko.AUTH_FAILED

    def test_auth_wrong_password(self):
        """Wrong password should fail."""
        server = SSHServer("10.0.0.1", username="admin", password="secret123")

        with patch.object(main.creds_logger, 'info'):
            with patch.object(main.alert_manager, 'send_alert'):
                result = server.check_auth_password("admin", "wrongpass")

        assert result == paramiko.AUTH_FAILED

    def test_auth_logs_attempt(self):
        """Authentication attempt should be logged."""
        server = SSHServer("192.168.1.50")

        with patch.object(main.creds_logger, 'info') as mock_log:
            with patch.object(main.alert_manager, 'send_alert'):
                server.check_auth_password("testuser", "testpass")

        mock_log.assert_called_once()
        log_message = mock_log.call_args[0][0]
        assert "192.168.1.50" in log_message
        assert "testuser" in log_message
        assert "testpass" in log_message

    def test_auth_sends_alert(self):
        """Authentication attempt should send alert."""
        server = SSHServer("10.0.0.5")

        with patch.object(main.creds_logger, 'info'):
            with patch.object(main.alert_manager, 'send_alert') as mock_alert:
                server.check_auth_password("root", "toor")

        mock_alert.assert_called_once()
        call_args = mock_alert.call_args
        assert call_args[0][0] == "login_attempt"
        assert call_args[0][1]["ip"] == "10.0.0.5"
        assert call_args[0][1]["username"] == "root"
        assert call_args[0][1]["password"] == "toor"


class TestShellRequest:
    """Tests for shell request handling."""

    def test_shell_request_accepted(self):
        """Shell request should be accepted."""
        server = SSHServer("10.0.0.1")
        result = server.check_channel_shell_request(MagicMock())
        assert result is True

    def test_shell_request_sets_event(self):
        """Shell request should set the event."""
        server = SSHServer("10.0.0.1")
        assert not server.event.is_set()

        server.check_channel_shell_request(MagicMock())

        assert server.event.is_set()


class TestPtyRequest:
    """Tests for PTY request handling."""

    def test_pty_request_accepted(self):
        """PTY request should be accepted."""
        server = SSHServer("10.0.0.1")
        result = server.check_channel_pty_request(
            MagicMock(),  # channel
            "xterm",      # term
            80,           # width
            24,           # height
            0,            # pixelwidth
            0,            # pixelheight
            b""           # modes
        )
        assert result is True


class TestExecRequest:
    """Tests for exec request handling."""

    def test_exec_request_accepted(self):
        """Exec request should be accepted."""
        server = SSHServer("10.0.0.1")
        result = server.check_channel_exec_request(
            MagicMock(),     # channel
            b"ls -la"        # command
        )
        assert result is True
