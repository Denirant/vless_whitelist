"""
Checker — сбор VLESS из git-репозитория igareck/vpn-configs-for-russia.
Клонирует/пуллит репо, читает файлы локально, фильтрует Russia/Anycast.
"""
import os, logging, subprocess
from pathlib import Path
from urllib.parse import urlparse, unquote

log = logging.getLogger("checker")

import threading
_progress_lock = threading.Lock()
_progress = {"active": False, "total": 0, "done": 0}

def get_progress() -> dict:
    with _progress_lock:
        return dict(_progress)

REPO_URL = os.environ.get("REPO_URL", "https://github.com/igareck/vpn-configs-for-russia.git")
REPO_DIR = Path(os.environ.get("REPO_DIR", "/app/data/repo"))

# Файлы для парсинга
SOURCE_FILES = [
    "WHITE-CIDR-RU-checked.txt",
]


def _node_label(uri: str) -> str:
    frag = urlparse(uri).fragment or ""
    return unquote(frag).lower()


def _clone_or_pull():
    """Клонировать репо или git pull если уже есть."""
    if (REPO_DIR / ".git").exists():
        log.info("git pull...")
        subprocess.run(["git", "-C", str(REPO_DIR), "pull", "--ff-only", "-q"],
                       capture_output=True, timeout=60)
    else:
        log.info(f"git clone {REPO_URL}...")
        REPO_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth=1", REPO_URL, str(REPO_DIR)],
                       capture_output=True, timeout=120)


def fetch_and_check() -> list[str]:
    """Пуллит репо, читает файлы, фильтрует Russia/Anycast, дедуплицирует."""
    try:
        _clone_or_pull()
    except Exception as e:
        log.error(f"git failed: {e}")
        if not REPO_DIR.exists():
            return []

    all_lines: list[str] = []
    for fname in SOURCE_FILES:
        fpath = REPO_DIR / fname
        if not fpath.exists():
            log.warning(f"Файл не найден: {fname}")
            continue
        text = fpath.read_text(encoding="utf-8", errors="ignore")
        lines = [l.strip() for l in text.splitlines()
                 if l.strip().startswith("vless://")]
        lines = [l for l in lines
                 if "russia" not in _node_label(l)
                 and "anycast" not in _node_label(l)]
        log.info(f"  {fname}: {len(lines)} VLESS")
        all_lines.extend(lines)

    # Дедупликация по host:port+uuid
    seen = set()
    unique = []
    for uri in all_lines:
        try:
            p = urlparse(uri)
            key = f"{p.hostname}:{p.port}:{p.username or p.netloc.split('@')[0]}"
            if key not in seen:
                seen.add(key)
                unique.append(uri)
        except Exception:
            unique.append(uri)

    log.info(f"Всего {len(unique)} уникальных VLESS")
    return unique
