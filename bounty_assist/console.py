"""UTF-8 output for Korean diagnostics, including redirected Windows consoles."""
import sys


def configure_console():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
