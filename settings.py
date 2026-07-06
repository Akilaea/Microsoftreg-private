import json
import os
from pathlib import Path


def get_config_path():
    """Return the active config path.

    Defaults to the original config.json so existing usage keeps working.
    Set OUTLOOK_REGISTER_CONFIG or pass --config from main.py for CTF test
    profiles.
    """
    return Path(os.environ.get("OUTLOOK_REGISTER_CONFIG", "config.json"))


def load_config():
    with get_config_path().open("r", encoding="utf-8") as f:
        return json.load(f)
