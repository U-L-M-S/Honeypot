"""
Pytest configuration and shared fixtures for honeypot tests.
"""

import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Add parent directory to path so we can import main
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def temp_log_dir(tmp_path):
    """Create a temporary log directory for tests."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    sessions_dir = log_dir / "sessions"
    sessions_dir.mkdir()
    return log_dir


@pytest.fixture
def mock_channel():
    """Create a mock SSH channel for testing."""
    channel = MagicMock()
    channel.recv.return_value = b""
    channel.send.return_value = None
    return channel


@pytest.fixture
def sample_keystrokes():
    """Sample keystroke data for testing bot detection."""
    return [
        {"time": 1000.0, "delay": 0, "char": "6c", "readable": "l"},
        {"time": 1000.1, "delay": 0.1, "char": "73", "readable": "s"},
        {"time": 1000.25, "delay": 0.15, "char": "0d", "readable": "\r"},
    ]


@pytest.fixture
def bot_keystrokes():
    """Keystroke data that mimics bot behavior (very consistent timing)."""
    # Generate 20 keystrokes with nearly identical timing (bot-like)
    keystrokes = []
    for i in range(20):
        keystrokes.append({
            "time": 1000.0 + (i * 0.02),  # Exactly 20ms apart
            "delay": 0.02 if i > 0 else 0,
            "char": "61",  # 'a'
            "readable": "a"
        })
    return keystrokes


@pytest.fixture
def human_keystrokes():
    """Keystroke data that mimics human behavior (variable timing)."""
    import random
    random.seed(42)  # For reproducibility

    keystrokes = []
    current_time = 1000.0
    for i in range(20):
        # Human typing: variable delays between 80ms and 300ms
        delay = random.uniform(0.08, 0.3) if i > 0 else 0
        current_time += delay
        keystrokes.append({
            "time": current_time,
            "delay": delay,
            "char": "61",
            "readable": "a"
        })
    return keystrokes
