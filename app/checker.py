"""
Checker — фильтрация VLESS через sing-box (по мотивам vless_config_updater).
Источник: zieng2/wl → vless_lite.txt
"""
import os, json, time, socket, asyncio, logging, tempfile, ipaddress
from urllib.parse import urlparse, parse_qs, unquote, quote
import httpx

log = logging.getLogger("checker")

# Прогресс обновления (потокобезопасный)
import threading
_progress_lock = threading.Lock()
_progress = {"active": False, "total": 0, "done": 0}

def get_progress() -> dict:
    with _progress_lock:
        return dict(_progress)

def _set_progress(active=False, total=0, done=0):
    with _progress_lock:
        _progress["active"] = active
        _progress["total"] = total
        _progress["done"] = done

def _inc_progress():
    with _progress_lock:
        _progress["done"] += 1

SING_BOX = os.environ.get("SING_BOX_PATH", "/usr/local/bin/sing-box")
MAX_NODES = int(os.environ.get("MAX_NODES", "45"))
SPEED_LIMIT = int(os.environ.get("SPEED_LIMIT", "3"))
CHECK_TIMEOUT = int(os.environ.get("CHECK_TIMEOUT", "6"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "10"))
RU_RATIO = float(os.environ.get("RU_RATIO", "0.25"))  # 25% RU, 75% non-RU
MAX_LATENCY = float(os.environ.get("MAX_LATENCY", "1.0"))
MAX_RESULT = int(os.environ.get("MAX_RESULT", "100"))
SOURCE_URLS = [
    s.strip() for s in os.environ.get(
        "SOURCE_URLS",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt,"
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt,"
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt"
    ).split(",") if s.strip()
]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _node_label(uri: str) -> str:
    frag = urlparse(uri).fragment or ""
    return unquote(frag).lower()


def _is_ru_node(uri: str) -> bool:
    label = _node_label(uri)
    ru_marks = (
        "ru", "russia", "moscow", "spb", "russian", "рос", "мск", "спб"
    )
    if any(mark in label for mark in ru_marks):
        return True
    try:
        host = urlparse(uri).hostname
        if host:
            ip = ipaddress.ip_address(host)
            return ip.is_private or str(ip).startswith(("5.", "31.", "37.", "45.", "46.", "62.", "77.", "78.", "79.", "80.", "81.", "82.", "83.", "84.", "85.", "87.", "88.", "89.", "90.", "91.", "92.", "93.", "94.", "95.", "109.", "176.", "178.", "185.", "188.", "193.", "194.", "195.", "212.", "213.", "217."))
    except Exception:
        pass
    return False


def _rename_node(uri: str, num: int) -> str:
    """Заменить #число в имени ноды на порядковый номер."""
    p = uri.split("#", 1)
    if len(p) < 2:
        return uri
    name = unquote(p[1]).strip()
    import re
    new_name = re.sub(r'#\d+', f'#{num}', name)
    if new_name == name:
        new_name = f"{name} #{num}"
    return f"{p[0]}#{quote(new_name)}"


def _pick_mixed(results: list[tuple[str, float]]) -> list[str]:
    """Вернуть до MAX_RESULT лучших нод, отсортированных по latency."""
    if not results:
        return []
    results.sort(key=lambda x: x[1])
    return [uri for uri, _ in results[:MAX_RESULT]]


def _vless_to_singbox(uri: str, port: int) -> dict | None:
    """vless:// URI → sing-box JSON config."""
    uri = uri.strip()
    if not uri.startswith("vless://"):
        return None
    try:
        p = urlparse(uri)
        uuid = p.username or p.netloc.split("@")[0]
        server, server_port = p.hostname, p.port
        if not server or not server_port:
            return None
        q = parse_qs(p.query)
        net = q.get("type", ["tcp"])[0]
        sec = q.get("security", [""])[0]
        flow = q.get("flow", [""])[0]
        sni = q.get("sni", [""])[0]
        fp = q.get("fp", ["chrome"])[0]

        tls, transport = {}, {}

        if sec == "reality":
            pbk = q.get("pbk", [""])[0]
            sid = q.get("sid", [""])[0]
            tls = {
                "enabled": True, "server_name": sni,
                "utls": {"enabled": True, "fingerprint": fp},
                "reality": {"enabled": True, "public_key": pbk, "short_id": sid},
            }
        elif sec == "tls":
            tls = {"enabled": True, "server_name": sni or server,
                   "utls": {"enabled": True, "fingerprint": fp}}
            alpn = q.get("alpn", [""])[0]
            if alpn:
                tls["alpn"] = alpn.split(",")

        if net == "ws":
            transport = {"type": "ws", "path": q.get("path", ["/"])[0],
                         "headers": {"Host": q.get("host", [server])[0]}}
        elif net == "grpc":
            transport = {"type": "grpc", "service_name": q.get("serviceName", [""])[0]}
        elif net == "httpupgrade":
            transport = {"type": "httpupgrade", "path": q.get("path", ["/"])[0],
                         "host": q.get("host", [server])[0]}

        out = {"type": "vless", "tag": "vless-out",
               "server": server, "server_port": server_port, "uuid": uuid}
        if flow:
            out["flow"] = flow
        if tls:
            out["tls"] = tls
        if transport:
            out["transport"] = transport

        return {
            "log": {"disabled": True},
            "inbounds": [{"type": "http", "tag": "http-in",
                          "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [out],
        }
    except Exception:
        return None


async def _measure_speed(proxy: str, timeout: int = 5) -> float:
    try:
        async with httpx.AsyncClient(proxy=proxy, timeout=timeout) as c:
            start = time.perf_counter()
            total = 0
            async with c.stream("GET", "https://speed.cloudflare.com/__down?bytes=5000000") as r:
                async for chunk in r.aiter_bytes():
                    total += len(chunk)
            dt = time.perf_counter() - start
            return (total * 8) / (dt * 1_000_000) if dt > 0 else 0.0
    except Exception:
        return 0.0


async def _check_one(uri: str, sem: asyncio.Semaphore) -> tuple[str, float, bool] | None:
    async with sem:
        port = _free_port()
        cfg = _vless_to_singbox(uri, port)
        if not cfg:
            _inc_progress()
            return None
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, dir="/tmp")
        try:
            json.dump(cfg, tmp); tmp.close()
            proc = await asyncio.create_subprocess_exec(
                SING_BOX, "run", "-c", tmp.name,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await asyncio.sleep(0.8)
            proxy = f"http://127.0.0.1:{port}"
            try:
                started = time.perf_counter()
                async with httpx.AsyncClient(proxy=proxy, timeout=CHECK_TIMEOUT) as c:
                    r = await c.get("https://www.cloudflare.com")
                    r.raise_for_status()
                latency = time.perf_counter() - started
                if latency > MAX_LATENCY:
                    return None
                if SPEED_LIMIT > 0:
                    spd = await _measure_speed(proxy)
                    if spd < SPEED_LIMIT:
                        return None
                log.info(f"OK: {latency:.3f}s {uri.strip()[:80]}")
                return uri.strip(), latency
            except Exception:
                return None
            finally:
                _inc_progress()
                try:
                    if proc.returncode is None:
                        proc.terminate()
                        try:
                            await asyncio.wait_for(proc.wait(), 2)
                        except asyncio.TimeoutError:
                            proc.kill()
                            await proc.wait()
                    else:
                        await proc.wait()
                except ProcessLookupError:
                    pass
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass


async def fetch_and_check() -> list[str]:
    """Скачать ноды из всех источников, проверить, вернуть до MAX_RESULT лучших URI."""
    all_lines: list[str] = []
    async with httpx.AsyncClient(timeout=15) as c:
        for url in SOURCE_URLS:
            try:
                log.info(f"Скачиваю ноды из {url[:60]}...")
                r = await c.get(url)
                r.raise_for_status()
                lines = [l.strip() for l in r.text.splitlines() if l.strip().startswith("vless://")]
                log.info(f"  → {len(lines)} VLESS из {url[:60]}")
                all_lines.extend(lines)
            except Exception as e:
                log.error(f"Не удалось скачать {url[:60]}: {e}")

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

    log.info(f"Всего {len(unique)} уникальных VLESS, проверяю (concurrency={CONCURRENCY})...")
    _set_progress(active=True, total=len(unique), done=0)
    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(*[_check_one(u, sem) for u in unique])
    _set_progress(active=False)
    good = [r for r in results if r]
    selected = _pick_mixed(good)
    log.info(f"Рабочих: {len(good)} из {len(unique)} | selected={len(selected)}")
    return selected
