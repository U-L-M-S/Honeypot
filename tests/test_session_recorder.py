"""
Tests for SessionRecorder class - session recording and bot detection.
"""

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# Import after path is set in conftest
import main
from main import SessionRecorder


class TestSessionRecorder:
    """Tests for SessionRecorder initialization and basic operations."""

    def test_init_creates_session_id(self):
        """Session recorder should generate a unique session ID."""
        recorder = SessionRecorder("192.168.1.1")
        assert recorder.session_id is not None
        assert len(recorder.session_id) == 8

    def test_init_with_custom_session_id(self):
        """Session recorder should accept a custom session ID."""
        recorder = SessionRecorder("192.168.1.1", session_id="custom12")
        assert recorder.session_id == "custom12"

    def test_init_stores_client_ip(self):
        """Session recorder should store the client IP."""
        recorder = SessionRecorder("10.0.0.5")
        assert recorder.client_ip == "10.0.0.5"

    def test_init_empty_collections(self):
        """Session recorder should initialize with empty collections."""
        recorder = SessionRecorder("192.168.1.1")
        assert recorder.keystrokes == []
        assert recorder.commands == []
        assert recorder.keystroke_timings == []


class TestKeystrokeRecording:
    """Tests for keystroke recording functionality."""

    def test_record_keystroke_stores_char(self):
        """Recording a keystroke should store the character."""
        recorder = SessionRecorder("192.168.1.1")
        recorder.record_keystroke(b"a")

        assert len(recorder.keystrokes) == 1
        assert recorder.keystrokes[0]["char"] == "61"  # hex for 'a'
        assert recorder.keystrokes[0]["readable"] == "a"

    def test_record_keystroke_first_has_zero_delay(self):
        """First keystroke should have zero delay."""
        recorder = SessionRecorder("192.168.1.1")
        recorder.record_keystroke(b"x")

        assert recorder.keystrokes[0]["delay"] == 0

    def test_record_keystroke_calculates_delay(self):
        """Subsequent keystrokes should calculate delay from previous."""
        recorder = SessionRecorder("192.168.1.1")

        recorder.record_keystroke(b"a")
        time.sleep(0.05)  # 50ms delay
        recorder.record_keystroke(b"b")

        assert len(recorder.keystroke_timings) == 1
        assert recorder.keystroke_timings[0] >= 0.04  # Allow some tolerance

    def test_record_keystroke_handles_special_chars(self):
        """Should handle special characters like newline and backspace."""
        recorder = SessionRecorder("192.168.1.1")

        recorder.record_keystroke(b"\r")  # Carriage return
        recorder.record_keystroke(b"\x7f")  # Backspace

        assert recorder.keystrokes[0]["char"] == "0d"
        assert recorder.keystrokes[1]["char"] == "7f"


class TestCommandRecording:
    """Tests for command recording functionality."""

    def test_record_command_stores_command(self):
        """Recording a command should store it with timestamp."""
        recorder = SessionRecorder("192.168.1.1")
        recorder.record_command("ls -la")

        assert len(recorder.commands) == 1
        assert recorder.commands[0]["command"] == "ls -la"
        assert "time" in recorder.commands[0]

    def test_record_multiple_commands(self):
        """Should be able to record multiple commands."""
        recorder = SessionRecorder("192.168.1.1")

        recorder.record_command("pwd")
        recorder.record_command("whoami")
        recorder.record_command("cat /etc/passwd")

        assert len(recorder.commands) == 3
        assert recorder.commands[0]["command"] == "pwd"
        assert recorder.commands[1]["command"] == "whoami"
        assert recorder.commands[2]["command"] == "cat /etc/passwd"


class TestBotDetection:
    """Tests for bot vs human detection based on keystroke timing."""

    def test_insufficient_data_not_bot(self):
        """With insufficient data, should not classify as bot."""
        recorder = SessionRecorder("192.168.1.1")

        # Only 5 keystrokes - not enough data
        for _ in range(5):
            recorder.record_keystroke(b"a")
            time.sleep(0.01)

        is_bot, reason = recorder.is_bot()
        assert is_bot is False
        assert reason == "insufficient_data"

    def test_superhuman_speed_detected_as_bot(self):
        """Very fast typing should be detected as bot."""
        recorder = SessionRecorder("192.168.1.1")

        # Simulate extremely fast typing (< 30ms between keystrokes)
        for i in range(15):
            recorder.keystroke_timings.append(0.02)  # 20ms delays

        is_bot, reason = recorder.is_bot()
        assert is_bot is True
        # Could be detected as either superhuman_speed or consistent_fast_timing
        assert reason in ("superhuman_speed", "consistent_fast_timing")

    def test_machine_precision_detected_as_bot(self):
        """Perfectly regular timing should be detected as bot."""
        recorder = SessionRecorder("192.168.1.1")

        # Simulate machine-like precision (exactly same delay each time)
        for i in range(15):
            recorder.keystroke_timings.append(0.1)  # Exactly 100ms each

        is_bot, reason = recorder.is_bot()
        assert is_bot is True
        assert reason == "machine_precision"

    def test_human_like_typing_not_bot(self):
        """Variable typing speed should be classified as human."""
        recorder = SessionRecorder("192.168.1.1")

        # Simulate human-like variable timing
        import random
        random.seed(42)
        for i in range(15):
            recorder.keystroke_timings.append(random.uniform(0.1, 0.3))

        is_bot, reason = recorder.is_bot()
        assert is_bot is False
        assert reason == "human_like"

    def test_consistent_fast_timing_detected_as_bot(self):
        """Consistent fast timing should be detected as bot."""
        recorder = SessionRecorder("192.168.1.1")

        # Fast and consistent (std < 0.01, avg < 0.1)
        for i in range(15):
            recorder.keystroke_timings.append(0.05 + (i * 0.001))

        is_bot, reason = recorder.is_bot()
        assert is_bot is True


class TestSessionSave:
    """Tests for saving session recordings."""

    def test_save_creates_json_file(self, tmp_path):
        """Saving session should create a JSON file."""
        # Patch SESSIONS_DIR to use temp directory
        with patch.object(main, 'SESSIONS_DIR', tmp_path):
            recorder = SessionRecorder("192.168.1.1", session_id="test1234")
            recorder.record_command("ls")

            session_data = recorder.save()

            # Check file was created
            files = list(tmp_path.glob("*.json"))
            assert len(files) == 1
            assert "test1234" in files[0].name

    def test_save_returns_session_data(self, tmp_path):
        """Saving session should return session data dictionary."""
        with patch.object(main, 'SESSIONS_DIR', tmp_path):
            recorder = SessionRecorder("10.0.0.1", session_id="abc12345")
            recorder.record_command("pwd")
            recorder.record_command("whoami")

            session_data = recorder.save()

            assert session_data["session_id"] == "abc12345"
            assert session_data["client_ip"] == "10.0.0.1"
            assert session_data["command_count"] == 2
            assert "start_time" in session_data
            assert "end_time" in session_data
            assert "duration_seconds" in session_data

    def test_save_includes_bot_detection(self, tmp_path):
        """Saved session should include bot detection results."""
        with patch.object(main, 'SESSIONS_DIR', tmp_path):
            recorder = SessionRecorder("192.168.1.1")

            session_data = recorder.save()

            assert "is_bot" in session_data
            assert "bot_detection_reason" in session_data

    def test_save_includes_timing_stats(self, tmp_path):
        """Saved session should include timing statistics."""
        with patch.object(main, 'SESSIONS_DIR', tmp_path):
            recorder = SessionRecorder("192.168.1.1")
            recorder.keystroke_timings = [0.1, 0.15, 0.12, 0.11]

            session_data = recorder.save()

            assert "timing_stats" in session_data
            stats = session_data["timing_stats"]
            assert "avg_delay" in stats
            assert "std_delay" in stats
            assert "min_delay" in stats
            assert "max_delay" in stats

    def test_saved_file_is_valid_json(self, tmp_path):
        """Saved session file should be valid JSON."""
        with patch.object(main, 'SESSIONS_DIR', tmp_path):
            recorder = SessionRecorder("192.168.1.1")
            recorder.record_command("test")
            recorder.save()

            files = list(tmp_path.glob("*.json"))
            with open(files[0], 'r') as f:
                data = json.load(f)

            assert isinstance(data, dict)
            assert "session_id" in data
