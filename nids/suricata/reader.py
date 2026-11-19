"""Incremental EVE log tailer with offset tracking and rotation detection.

Safely tails Suricata eve.json in binary mode, tracks exact byte offsets across restarts,
detects log rotation and file truncation, and safely buffers partial/incomplete lines.
"""

import json
import logging
import os
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("nids.suricata.reader")


class EveLogReader:
    """Manages low-level file seeking, offset tracking, and line buffering for eve.json."""

    def __init__(
        self,
        file_path: str,
        state_path: Optional[str] = None,
        max_bytes_per_poll: int = 1024 * 1024,  # 1 MB max read chunk
    ):
        """Initialize EVE log reader.

        Args:
            file_path: Absolute or relative path to the eve.json file.
            state_path: Optional JSON file path to persist byte offset across restarts.
            max_bytes_per_poll: Maximum bytes to read in a single poll cycle to bound memory.
        """
        self.file_path = file_path
        self.state_path = state_path
        self.max_bytes_per_poll = max_bytes_per_poll
        self.offset: int = 0
        self._last_inode_or_mtime: Optional[float] = None

        if self.state_path:
            self.load_state()

    def load_state(self) -> None:
        """Load persisted offset from state_path if available."""
        if not self.state_path or not os.path.exists(self.state_path):
            return

        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
                if isinstance(state, dict):
                    saved_path = state.get("file_path")
                    # Only restore offset if it matches the current file
                    if not saved_path or os.path.abspath(saved_path) == os.path.abspath(self.file_path):
                        self.offset = int(state.get("offset", 0))
                        logger.info("Restored Suricata EVE offset: %d from %s", self.offset, self.state_path)
        except Exception as exc:
            logger.warning("Could not load Suricata state from %s: %s", self.state_path, exc)
            self.offset = 0

    def save_state(self) -> None:
        """Persist current offset to state_path."""
        if not self.state_path:
            return

        try:
            state_dir = os.path.dirname(os.path.abspath(self.state_path))
            if state_dir:
                os.makedirs(state_dir, exist_ok=True)

            state = {
                "file_path": os.path.abspath(self.file_path),
                "offset": self.offset,
            }
            # Write atomically via temp file
            tmp_path = f"{self.state_path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(state, f)
            os.replace(tmp_path, self.state_path)
        except Exception as exc:
            logger.warning("Failed saving Suricata state to %s: %s", self.state_path, exc)

    def reset_offset(self, offset: int = 0) -> None:
        """Manually reset the read offset."""
        self.offset = max(0, offset)
        self.save_state()

    def read_new_lines(self) -> List[str]:
        """Read newly appended complete lines from the EVE file.

        Detects file shrinkage/rotation and resets offset automatically.
        Only complete lines ending with newline are returned; partial lines remain unconsumed.

        Returns:
            List of decoded UTF-8 string lines.
        """
        if not os.path.exists(self.file_path):
            return []

        try:
            stat_info = os.stat(self.file_path)
            current_size = stat_info.st_size
            current_mtime = stat_info.st_mtime
        except OSError as exc:
            logger.warning("Could not inspect EVE file %s: %s", self.file_path, exc)
            return []

        # 1. Truncation / Rotation Check
        if current_size < self.offset:
            logger.info(
                "Suricata EVE log truncated or rotated (size %d < offset %d). Resetting offset to 0.",
                current_size,
                self.offset,
            )
            self.offset = 0

        # No new bytes written
        if current_size == self.offset:
            return []

        bytes_to_read = min(current_size - self.offset, self.max_bytes_per_poll)

        lines: List[str] = []
        try:
            with open(self.file_path, "rb") as f:
                f.seek(self.offset)
                chunk = f.read(bytes_to_read)

                if not chunk:
                    return []

                # Find last newline in chunk
                last_nl = chunk.rfind(b"\n")
                if last_nl == -1:
                    # Incomplete line; do not advance offset
                    logger.debug("Partial line encountered in EVE log; waiting for newline.")
                    return []

                # Slice strictly up to and including the last newline
                valid_bytes = chunk[: last_nl + 1]
                consumed_len = len(valid_bytes)

                # Decode into strings
                decoded_text = valid_bytes.decode("utf-8", errors="replace")
                raw_lines = decoded_text.splitlines()

                for line in raw_lines:
                    cleaned = line.strip()
                    if cleaned:
                        lines.append(cleaned)

                # Advance offset by exact byte length consumed
                self.offset += consumed_len
                self._last_inode_or_mtime = current_mtime

                if lines and self.state_path:
                    self.save_state()

        except Exception as exc:
            logger.error("Error reading Suricata EVE log %s: %s", self.file_path, exc)

        return lines

