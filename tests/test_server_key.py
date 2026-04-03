"""
Tests for SSH server key management.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import paramiko

import main
from main import get_or_create_server_key


class TestServerKeyManagement:
    """Tests for SSH server key generation and loading."""

    def test_creates_key_if_not_exists(self, tmp_path):
        """Should create new RSA key if file doesn't exist."""
        key_path = tmp_path / "server.key"

        with patch.object(main, 'SERVER_KEY_PATH', key_path):
            with patch.object(main.console, 'info'):
                key = get_or_create_server_key()

        assert key is not None
        assert isinstance(key, paramiko.RSAKey)
        assert key_path.exists()

    def test_loads_existing_key(self, tmp_path):
        """Should load existing key if file exists."""
        key_path = tmp_path / "server.key"

        # Create a key first
        original_key = paramiko.RSAKey.generate(2048)
        original_key.write_private_key_file(str(key_path))
        original_fingerprint = original_key.get_fingerprint()

        with patch.object(main, 'SERVER_KEY_PATH', key_path):
            loaded_key = get_or_create_server_key()

        assert loaded_key.get_fingerprint() == original_fingerprint

    def test_generated_key_is_2048_bits(self, tmp_path):
        """Generated key should be 2048 bits."""
        key_path = tmp_path / "server.key"

        with patch.object(main, 'SERVER_KEY_PATH', key_path):
            with patch.object(main.console, 'info'):
                key = get_or_create_server_key()

        assert key.get_bits() == 2048

    def test_key_file_permissions(self, tmp_path):
        """Key file should be created with proper permissions."""
        key_path = tmp_path / "server.key"

        with patch.object(main, 'SERVER_KEY_PATH', key_path):
            with patch.object(main.console, 'info'):
                get_or_create_server_key()

        # File should exist and be readable
        assert key_path.exists()
        assert key_path.is_file()

    def test_logs_when_creating_new_key(self, tmp_path):
        """Should log message when creating new key."""
        key_path = tmp_path / "server.key"

        with patch.object(main, 'SERVER_KEY_PATH', key_path):
            with patch.object(main.console, 'info') as mock_log:
                get_or_create_server_key()

        mock_log.assert_called_once()
        assert "Generating" in mock_log.call_args[0][0]

    def test_no_log_when_loading_existing_key(self, tmp_path):
        """Should not log when loading existing key."""
        key_path = tmp_path / "server.key"

        # Create key first
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(key_path))

        with patch.object(main, 'SERVER_KEY_PATH', key_path):
            with patch.object(main.console, 'info') as mock_log:
                get_or_create_server_key()

        mock_log.assert_not_called()
