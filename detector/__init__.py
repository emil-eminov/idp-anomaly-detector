"""Detect account takeover patterns in identity-provider login logs."""

from .loader import load_csv
from .models import Event, Finding
from .rules import run_all

__all__ = ["Event", "Finding", "load_csv", "run_all"]
__version__ = "0.1.0"
