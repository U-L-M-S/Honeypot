"""
Tests for logging setup and configuration.
"""

import logging
from pathlib import Path
from unittest.mock import patch

import pytest

import main


class TestLoggingSetup:
    """Tests for logging configuration."""

    def test_creds_logger_exists(self):
        """Credentials logger should be configured."""
        assert main.creds_logger is not None
        assert isinstance(main.creds_logger, logging.Logger)

    def test_cmd_logger_exists(self):
        """Commands logger should be configured."""
        assert main.cmd_logger is not None
        assert isinstance(main.cmd_logger, logging.Logger)

    def test_http_logger_exists(self):
        """HTTP logger should be configured."""
        assert main.http_logger is not None
        assert isinstance(main.http_logger, logging.Logger)

    def test_downloads_logger_exists(self):
        """Downloads logger should be configured."""
        assert main.downloads_logger is not None
        assert isinstance(main.downloads_logger, logging.Logger)

    def test_alerts_logger_exists(self):
        """Alerts logger should be configured."""
        assert main.alerts_logger is not None
        assert isinstance(main.alerts_logger, logging.Logger)

    def test_console_logger_exists(self):
        """Console logger should be configured."""
        assert main.console is not None
        assert isinstance(main.console, logging.Logger)


class TestLoggerLevels:
    """Tests for logger levels."""

    def test_creds_logger_level(self):
        """Credentials logger should be INFO level."""
        assert main.creds_logger.level == logging.INFO

    def test_cmd_logger_level(self):
        """Commands logger should be INFO level."""
        assert main.cmd_logger.level == logging.INFO

    def test_console_logger_level(self):
        """Console logger should be INFO level."""
        assert main.console.level == logging.INFO


class TestLogPaths:
    """Tests for log file paths."""

    def test_creds_log_path(self):
        """Credentials log path should be correct."""
        assert main.CREDS_LOG == main.LOG_DIR / "credentials.log"

    def test_commands_log_path(self):
        """Commands log path should be correct."""
        assert main.COMMANDS_LOG == main.LOG_DIR / "commands.log"

    def test_http_log_path(self):
        """HTTP log path should be correct."""
        assert main.HTTP_LOG == main.LOG_DIR / "http_attempts.log"

    def test_downloads_log_path(self):
        """Downloads log path should be correct."""
        assert main.DOWNLOADS_LOG == main.LOG_DIR / "malware_urls.log"

    def test_alerts_log_path(self):
        """Alerts log path should be correct."""
        assert main.ALERTS_LOG == main.LOG_DIR / "alerts.log"


class TestDirectorySetup:
    """Tests for directory creation."""

    def test_log_dir_exists(self):
        """Log directory should exist."""
        assert main.LOG_DIR.exists()
        assert main.LOG_DIR.is_dir()

    def test_static_dir_exists(self):
        """Static directory should exist."""
        assert main.STATIC_DIR.exists()
        assert main.STATIC_DIR.is_dir()

    def test_sessions_dir_exists(self):
        """Sessions directory should exist."""
        assert main.SESSIONS_DIR.exists()
        assert main.SESSIONS_DIR.is_dir()

    def test_sessions_dir_inside_logs(self):
        """Sessions directory should be inside logs."""
        assert main.SESSIONS_DIR.parent == main.LOG_DIR


class TestColoredFormatter:
    """Tests for ColoredFormatter class."""

    def test_colors_defined(self):
        """All log levels should have colors defined."""
        formatter = main.ColoredFormatter()

        assert "DEBUG" in formatter.COLORS
        assert "INFO" in formatter.COLORS
        assert "WARNING" in formatter.COLORS
        assert "ERROR" in formatter.COLORS
        assert "CRITICAL" in formatter.COLORS
        assert "RESET" in formatter.COLORS

    def test_colors_are_ansi_codes(self):
        """Colors should be ANSI escape codes."""
        formatter = main.ColoredFormatter()

        for level, color in formatter.COLORS.items():
            assert color.startswith("\033[")

    def test_format_adds_color(self):
        """Format should add color to message."""
        formatter = main.ColoredFormatter("%(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)
        assert "\033[" in formatted  # Contains ANSI code


class TestConfiguration:
    """Tests for configuration constants."""

    def test_ssh_banner(self):
        """SSH banner should look realistic."""
        assert "SSH-2.0" in main.SSH_BANNER
        assert "OpenSSH" in main.SSH_BANNER

    def test_fake_hostname(self):
        """Fake hostname should be set."""
        assert main.FAKE_HOSTNAME is not None
        assert len(main.FAKE_HOSTNAME) > 0

    def test_fake_username(self):
        """Fake username should be set."""
        assert main.FAKE_USERNAME is not None
        assert len(main.FAKE_USERNAME) > 0

    def test_fake_working_dir(self):
        """Fake working directory should be a valid path."""
        assert main.FAKE_WORKING_DIR.startswith("/")

    def test_server_key_path(self):
        """Server key path should be in static directory."""
        assert main.SERVER_KEY_PATH.parent == main.STATIC_DIR
        assert "server.key" in str(main.SERVER_KEY_PATH)
