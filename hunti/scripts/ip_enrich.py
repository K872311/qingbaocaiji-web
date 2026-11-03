"""
IP 画像富化（不入库）

从公开源下载网段 / IP 列表，查 IP 时给出属性标签：
  威胁: Spamhaus DROP（被劫持网段）
  资产: Tor 出口、CDN（Cloudflare / CloudFront / Fastly）、
        云托管（AWS / Azure / Google / Oracle / 阿里云）、
        VPN（X4BNet / NordVPN / ProtonVPN）、开放代理（HTTP / SOCKS5）、公共 DNS
另有 AbuseIPDB 实时查询（需 Key，带本地缓存与每日配额保护）。

数据目录: output/ip_enrich/
  --to-db 时整体同步进主库，type=ip_profile、source=IP画像·<标签>。
  面板把这类记录当属性展示，不参与恶意判定；也不占 type=ip 的唯一键。

用法:
  python -X utf8 ip_enrich.py --update --to-db     # 下载并同步入库（run_all 7f）
  python -X utf8 ip_enrich.py --update --force
  python -X utf8 ip_enrich.py --lookup 1.1.1.1
  python -X utf8 ip_enrich.py --abuseipdb 1.2.3.4  # 实时查 AbuseIPDB
  python -X utf8 ip_enrich.py --status

AbuseIPDB Key: 环境变量 ABUSEIPDB_API_KEY，或 config/abuseipdb_api_key.txt
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "output", "ip_enrich")
META_PATH = os.path.join(DATA_DIR, "meta.json")
ABUSE_CACHE_PATH = os.path.join(DATA_DIR, "abuseipdb_cache.json")
ABUSE_KEY_FILE = os.path.join(BASE_DIR, "config", "abuseipdb_api_key.txt")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HuntiIOC/1.0"
TIMEOUT = 60

_CIDR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_EXIT_RE = re.compile(r"^ExitAddress\s+(\S+)")
_AZURE_LINK_RE = re.compile(
    r"https://download\.microsoft\.com/download/[^\s\"']+ServiceTags_Public_\d+\.json")

# 公共 DNS / 基建（少量手工维护，避免把 8.8.8.8 之类当成可疑出口）
STATIC_INFRA = (
    ("8.8.8.8", "Google Public DNS"), ("8.8.4.4", "Google Public DNS"),
    ("1.1.1.1", "Cloudflare DNS"), ("1.0.0.1", "Cloudflare DNS"),
    ("9.9.9.9", "Quad9 DNS"), ("149.112.112.112", "Quad9 DNS"),
    ("208.67.222.222", "OpenDNS"), ("208.67.220.220", "OpenDNS"),
    ("94.140.14.14", "AdGuard DNS"), ("94.140.15.15", "AdGuard DNS"),
    ("114.114.114.114", "114 DNS"), ("114.114.115.115", "114 DNS"),
    ("223.5.5.5", "阿里 DNS"), ("223.6.6.6", "阿里 DNS"),
    ("119.29.29.29", "腾讯 DNSPod"), ("182.254.116.116", "腾讯 DNSPod"),
    ("180.76.76.76", "百度 DNS"), ("101.226.4.6", "360 DNS"),
)


# ── 源定义 ────────────────────────────────────────────────────────────
# fetch: 下载键；多个 feed 可共用同一下载（如 AWS JSON 同时出 CDN 与云段）
DOWNLOADS = {
    "spamhaus_drop": {"url": "https://www.spamhaus.org/drop/drop.txt",
                      "file": "spamhaus_drop.txt", "stale_hours": 24},
    "tor_exits": {"url": "https://check.torproject.org/exit-addresses",
                  "fallbacks": ["https://www.dan.me.uk/torlist/?exit"],
                  "file": "tor_exits.txt", "stale_hours": 24},
    "cloudflare": {"url": "https://www.cloudflare.com/ips-v4",
                   "file": "cdn_cloudflare.txt", "stale_hours": 168},
    "aws": {"url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
            "file": "aws_ip_ranges.json", "stale_hours": 168, "json": True},
    "fastly": {"url": "https://api.fastly.com/public-ip-list",
               "file": "cdn_fastly.json", "stale_hours": 168, "json": True},
    "gcp": {"url": "https://www.gstatic.com/ipranges/goog.json",
            "file": "cloud_gcp.json", "stale_hours": 168, "json": True},
    "azure": {"url": "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",
              "file": "cloud_azure.json", "stale_hours": 336, "special": "azure"},
    "oracle": {"url": "https://docs.oracle.com/iaas/tools/public_ip_ranges.json",
               "file": "cloud_oracle.json", "stale_hours": 168, "json": True},
    "alibaba": {"url": "https://cloud-ip-ranges.com/download/alibaba.txt",
                "file": "cloud_alibaba.txt", "stale_hours": 168, "cidr_guard": True},
    "x4bnet_vpn": {"url": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
                   "file": "vpn_x4bnet.txt", "stale_hours": 168},
    "nordvpn": {"url": "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/VPN/NordVPN/nordvpn_ips_list.csv",
                "file": "vpn_nordvpn.csv", "stale_hours": 168},
    "protonvpn": {"url": "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/VPN/ProtonVPN/protonvpn_ip_list.csv",
                  "file": "vpn_protonvpn.csv", "stale_hours": 168},
    "proxy_http": {"url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
                   "file": "proxy_http.txt", "stale_hours": 24},
    "proxy_socks5": {"url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
                     "file": "proxy_socks5.txt", "stale_hours": 24},
}

# (feed 名, 下载键, 解析器, kind, label, flag, provider)
FEEDS = (
    ("spamhaus_drop", "spamhaus_drop", "spamhaus", "threat", "Spamhaus DROP", "drop", None),
    ("tor_exits", "tor_exits", "tor", "asset", "Tor 出口", "tor", None),
    ("cdn_cloudflare", "cloudflare", "cidr_lines", "asset", "CDN · Cloudflare", "cdn", "Cloudflare"),
    ("cdn_cloudfront", "aws", "aws_cloudfront", "asset", "CDN · CloudFront", "cdn", "CloudFront"),
    ("cdn_fastly", "fastly", "fastly", "asset", "CDN · Fastly", "cdn", "Fastly"),
    ("cloud_aws", "aws", "aws_all", "asset", "云托管 · AWS", "cloud", "AWS"),
    ("cloud_azure", "azure", "azure", "asset", "云托管 · Azure", "cloud", "Azure"),
    ("cloud_gcp", "gcp", "gcp", "asset", "云托管 · Google", "cloud", "Google"),
    ("cloud_oracle", "oracle", "oracle", "asset", "云托管 · Oracle", "cloud", "Oracle"),
    ("cloud_alibaba", "alibaba", "cidr_lines", "asset", "云托管 · 阿里云", "cloud", "Alibaba"),
    ("vpn_x4bnet", "x4bnet_vpn", "cidr_lines", "asset", "VPN", "vpn", None),
    ("vpn_nordvpn", "nordvpn", "csv_first", "asset", "VPN · NordVPN", "vpn", "NordVPN"),
    ("vpn_protonvpn", "protonvpn", "csv_first2", "asset", "VPN · ProtonVPN", "vpn", "ProtonVPN"),
    ("proxy_http", "proxy_http", "ip_port", "asset", "开放代理 · HTTP", "proxy", None),
    ("proxy_socks5", "proxy_socks5", "ip_port", "asset", "开放代理 · SOCKS5", "proxy", None),
)

_lock = threading.Lock()
_abuse_lock = threading.Lock()
_index = None
_index_mtime = 0.0


class IntervalIndex:
    """IPv4 画像索引：精确 IP 字典 + 按首字节分桶的网段（/0~/7 的超大网段单独一桶）。"""

    __slots__ = ("_ips", "_buckets", "_wide", "_n")

    def __init__(self):
        self._ips: dict[int, list[dict]] = {}
        self._buckets: dict[int, list[tuple[int, int, dict]]] = {}
        self._wide: list[tuple[int, int, dict]] = []
        self._n = 0

    def add_cidr(self, cidr: str, meta: dict) -> bool:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
        if net.version != 4:
            return False
        start, end = int(net.network_address), int(net.broadcast_address)
        if start == end:
            self._ips.setdefault(start, []).append(meta)
        elif net.prefixlen < 8:
            self._wide.append((start, end, meta))
        else:
            self._buckets.setdefault(start >> 24, []).append((start, end, meta))
        self._n += 1
        return True

    def add_ip(self, ip: str, meta: dict) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.version != 4:
            return False
        self._ips.setdefault(int(addr), []).append(meta)
        self._n += 1
        return True

    def lookup(self, ip: str) -> list[dict]:
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return []
        hits, seen = [], set()

        def _add(meta, cidr):
            key = meta["source"]
            if key not in seen:
                seen.add(key)
                hits.append(dict(meta, cidr=cidr))

        for meta in self._ips.get(n, []):
            _add(meta, ip + "/32")
        for start, end, meta in self._buckets.get(n >> 24, ()):
            if start <= n <= end:
                _add(meta, _to_cidr(start, end))
        for start, end, meta in self._wide:
            if start <= n <= end:
                _add(meta, _to_cidr(start, end))
        return hits

    def __len__(self):
        return self._n


def _to_cidr(start: int, end: int) -> str:
    size = end - start + 1
    prefix = 32 - (size.bit_length() - 1)
    return "{}/{}".format(ipaddress.IPv4Address(start), prefix)


# ── 下载 ──────────────────────────────────────────────────────────────

def _http_get(url: str, headers: dict | None = None) -> bytes:
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read()


def _fetch_azure(page_url: str) -> bytes:
    """Azure Service Tags：确认页里拿当天的 ServiceTags_Public_<date>.json 直链。"""
    html = _http_get(page_url).decode("utf-8", errors="replace")
    m = _AZURE_LINK_RE.search(html)
    if not m:
        raise RuntimeError("确认页里没找到 ServiceTags_Public 链接")
    return _http_get(m.group(0))


def _validate(name: str, cfg: dict, raw: bytes):
    if not raw.strip():
        raise RuntimeError("empty response")
    if cfg.get("json") or cfg.get("special") == "azure":
        try:
            json.loads(raw)
        except ValueError:
            raise RuntimeError("返回的不是 JSON（可能是错误页）")
    if cfg.get("cidr_guard") and not _parse_cidr_lines(raw):
        raise RuntimeError("没有任何 CIDR 行（可能是维护页）")


def _path(dl_key: str) -> str:
    return os.path.join(DATA_DIR, DOWNLOADS[dl_key]["file"])


def _load_meta() -> dict:
    try:
        with open(META_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"downloads": {}}


def _save_meta(meta: dict):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


def update_feeds(force: bool = False) -> dict[str, Any]:
    """下载各源到 output/ip_enrich/；失败时保留旧文件。"""
    os.makedirs(DATA_DIR, exist_ok=True)
    meta = _load_meta()
    dl_meta = meta.setdefault("downloads", {})
    stats = {"ok": [], "skip": [], "fail": []}
    now = time.time()
    for key, cfg in DOWNLOADS.items():
        path = _path(key)
        if not force and os.path.isfile(path):
            age_h = (now - os.path.getmtime(path)) / 3600
            if age_h < cfg.get("stale_hours", 48) * 0.9:
                stats["skip"].append(key)
                continue
        urls = [cfg["url"]] + list(cfg.get("fallbacks") or [])
        raw, used, err = None, None, None
        for url in urls:
            try:
                print(f"  下载 {key}: {url}", flush=True)
                data = _fetch_azure(url) if cfg.get("special") == "azure" else _http_get(url)
                _validate(key, cfg, data)
                raw, used = data, url
                break
            except Exception as e:
                err = e
                print(f"  [WARN] {key} 失败: {e}", flush=True)
        if raw is None:
            stats["fail"].append({"name": key, "error": str(err)})
            continue
        tmp = path + ".dl"
        with open(tmp, "wb") as f:
            f.write(raw)
        os.replace(tmp, path)
        dl_meta[key] = {"updated_at": datetime.now(timezone.utc).isoformat(),
                        "bytes": len(raw), "url": used}
        stats["ok"].append(key)
    meta["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_meta(meta)
    global _index, _index_mtime
    with _lock:
        _index, _index_mtime = None, 0.0
    return stats


# ── 解析 ──────────────────────────────────────────────────────────────

def _lines(raw: bytes):
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        s = line.strip()
        if s and not s.startswith(("#", ";")):
            yield s


def _parse_spamhaus(raw: bytes) -> list[str]:
    out = []
    for s in _lines(raw):
        s = s.split(";", 1)[0].strip()
        if _CIDR_RE.match(s):
            out.append(s)
    return out


def _parse_tor(raw: bytes) -> list[str]:
    """兼容 Tor Project ExitAddress 格式与 dan.me.uk 纯 IP 列表。"""
    out, seen = [], set()
    for s in _lines(raw):
        m = _EXIT_RE.match(s)
        ip = m.group(1) if m else s.split()[0]
        if _IPV4_RE.match(ip) and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _parse_cidr_lines(raw: bytes) -> list[str]:
    return [s.split()[0] for s in _lines(raw) if _CIDR_RE.match(s.split()[0])]


def _parse_ip_port(raw: bytes) -> list[str]:
    out, seen = [], set()
    for s in _lines(raw):
        ip = s.split()[0].split(":")[0]
        if _IPV4_RE.match(ip) and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _parse_csv_cols(raw: bytes, ncols: int) -> list[str]:
    out, seen = [], set()
    for s in _lines(raw):
        if s.lower().startswith("src_ip"):
            continue
        for col in s.split(",")[:ncols]:
            ip = col.strip()
            if _IPV4_RE.match(ip) and ip not in seen:
                seen.add(ip)
                out.append(ip)
    return out


def _parse_aws(raw: bytes, cloudfront_only: bool) -> list[str]:
    data = json.loads(raw)
    return [p["ip_prefix"] for p in data.get("prefixes", [])
            if p.get("ip_prefix") and (not cloudfront_only or p.get("service") == "CLOUDFRONT")]


def _parse_fastly(raw: bytes) -> list[str]:
    return [x for x in json.loads(raw).get("addresses", []) if _CIDR_RE.match(x)]


def _parse_gcp(raw: bytes) -> list[str]:
    return [p["ipv4Prefix"] for p in json.loads(raw).get("prefixes", []) if p.get("ipv4Prefix")]


def _parse_azure(raw: bytes) -> list[str]:
    for v in json.loads(raw).get("values", []):
        # 只取总标签 AzureCloud，区域标签是它的子集
        if v.get("name") == "AzureCloud":
            return [p for p in (v.get("properties") or {}).get("addressPrefixes", []) if _CIDR_RE.match(p)]
    return []


def _parse_oracle(raw: bytes) -> list[str]:
    out = []
    for region in json.loads(raw).get("regions", []):
        for c in region.get("cidrs", []):
            cidr = c.get("cidr") if isinstance(c, dict) else c
            if cidr and _CIDR_RE.match(cidr):
                out.append(cidr)
    return out


_PARSERS = {
    "spamhaus": _parse_spamhaus,
    "tor": _parse_tor,
    "cidr_lines": _parse_cidr_lines,
    "ip_port": _parse_ip_port,
    "csv_first": lambda raw: _parse_csv_cols(raw, 1),
    "csv_first2": lambda raw: _parse_csv_cols(raw, 2),
    "aws_cloudfront": lambda raw: _parse_aws(raw, True),
    "aws_all": lambda raw: _parse_aws(raw, False),
    "fastly": _parse_fastly,
    "gcp": _parse_gcp,
    "azure": _parse_azure,
    "oracle": _parse_oracle,
}


def build_index(verbose: bool = True) -> IntervalIndex:
    idx = IntervalIndex()
    counts = {}
    raw_cache: dict[str, bytes | None] = {}
    for name, dl_key, parser, kind, label, flag, provider in FEEDS:
        if dl_key not in raw_cache:
            p = _path(dl_key)
            raw_cache[dl_key] = open(p, "rb").read() if os.path.isfile(p) else None
        raw = raw_cache[dl_key]
        if not raw:
            counts[name] = 0
            continue
        try:
            items = _PARSERS[parser](raw)
        except Exception as e:
            print(f"  [WARN] 解析 {name} 失败: {e}")
            counts[name] = 0
            continue
        meta = {"source": name, "kind": kind, "label": label, "flag": flag}
        if provider:
            meta["provider"] = provider
        n = 0
        for item in items:
            if idx.add_cidr(item if "/" in item else item + "/32", meta):
                n += 1
        counts[name] = n
    for ip, svc in STATIC_INFRA:
        idx.add_ip(ip, {"source": "infra_" + svc, "kind": "asset",
                        "label": "公共 DNS · " + svc, "flag": "infra", "provider": svc})
    counts["infra"] = len(STATIC_INFRA)
    if verbose:
        print(f"IP 画像索引: {len(idx)} 条 " + ", ".join(f"{k}={v}" for k, v in counts.items() if v))
    return idx


def _data_mtime() -> float:
    m = 0.0
    for key in DOWNLOADS:
        p = _path(key)
        if os.path.isfile(p):
            m = max(m, os.path.getmtime(p))
    return m


def get_index() -> IntervalIndex:
    global _index, _index_mtime
    with _lock:
        mtime = _data_mtime()
        if _index is None or mtime > _index_mtime:
            _index = build_index(verbose=_index is None)
            _index_mtime = mtime
        return _index


def lookup(ip: str) -> dict[str, Any]:
    """查单个 IPv4，返回画像标签（出错返回空结构，不抛）。"""
    if not ip or not _IPV4_RE.match(ip):
        return {"tags": [], "flags": {}, "summary": "", "loaded": False}
    idx = get_index()
    hits = idx.lookup(ip)
    hits.sort(key=lambda h: (0 if h["kind"] == "threat" else 1, h["label"]))
    flags: dict[str, Any] = {}
    for h in hits:
        flags[h["flag"]] = h.get("provider") or True
    return {
        "tags": [{"kind": h["kind"], "label": h["label"], "source": h["source"],
                  "cidr": h.get("cidr"), "provider": h.get("provider"), "flag": h["flag"]} for h in hits],
        "flags": flags,
        "summary": " · ".join(h["label"] for h in hits),
        "loaded": len(idx) > len(STATIC_INFRA),
        "updated_at": _load_meta().get("updated_at"),
    }


def is_shared_infra(ip: str) -> bool:
    """CDN 边缘 / 公共 DNS：采集脚本入库前用来剔除共享 IP。"""
    flags = lookup(ip).get("flags") or {}
    return bool(flags.get("cdn") or flags.get("infra"))


# ── AbuseIPDB 实时查询 ───────────────────────────────────────────────

def load_abuseipdb_key() -> str:
    key = (os.environ.get("ABUSEIPDB_API_KEY") or "").strip()
    if key:
        return key
    try:
        with open(ABUSE_KEY_FILE, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#") and "your_" not in s.lower():
                    return s
    except OSError:
        pass
    return ""


def _abuse_cache() -> dict:
    try:
        with open(ABUSE_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"items": {}, "quota": {}}


def _abuse_save(cache: dict):
    os.makedirs(DATA_DIR, exist_ok=True)
    items = cache.get("items", {})
    if len(items) > 5000:
        keep = sorted(items.items(), key=lambda kv: kv[1].get("ts", 0))[-4000:]
        cache["items"] = dict(keep)
    tmp = ABUSE_CACHE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False)
    os.replace(tmp, ABUSE_CACHE_PATH)


def abuseipdb_check(ip: str, max_age_days: int = 90) -> dict[str, Any]:
    """AbuseIPDB /api/v2/check。缓存 24h；免费层 1000 次/天，默认本地限 900。"""
    key = load_abuseipdb_key()
    if not key:
        return {"configured": False}
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return {"configured": True, "error": "不是合法 IPv4"}
    if not addr.is_global:
        return {"configured": True, "error": "非公网 IP，不查询"}
    ttl = int(os.environ.get("ABUSEIPDB_CACHE_HOURS", "24")) * 3600
    daily_limit = int(os.environ.get("ABUSEIPDB_DAILY_LIMIT", "900"))
    with _abuse_lock:
        cache = _abuse_cache()
        hit = cache.get("items", {}).get(ip)
        if hit and time.time() - hit.get("ts", 0) < ttl:
            return dict(hit["data"], configured=True, cached=True)
        today = datetime.now().strftime("%Y-%m-%d")
        quota = cache.setdefault("quota", {})
        if quota.get("day") != today:
            quota.update({"day": today, "used": 0})
        if quota["used"] >= daily_limit:
            if hit:
                return dict(hit["data"], configured=True, cached=True, stale=True)
            return {"configured": True, "error": f"今日本地配额已用完（{daily_limit} 次）"}
        quota["used"] += 1
        _abuse_save(cache)
    qs = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": max_age_days})
    try:
        raw = _http_get("https://api.abuseipdb.com/api/v2/check?" + qs,
                        headers={"Key": key, "Accept": "application/json"})
        d = (json.loads(raw) or {}).get("data") or {}
    except urllib.error.HTTPError as e:
        msg = "Key 无效" if e.code in (401, 403) else ("触发限速" if e.code == 429 else f"HTTP {e.code}")
        return {"configured": True, "error": msg}
    except Exception as e:
        return {"configured": True, "error": str(e)[:120]}
    data = {
        "ip": ip,
        "score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "distinct_users": d.get("numDistinctUsers"),
        "last_reported_at": d.get("lastReportedAt"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "usage_type": d.get("usageType"),
        "is_tor": d.get("isTor"),
        "is_whitelisted": d.get("isWhitelisted"),
        "link": "https://www.abuseipdb.com/check/" + ip,
    }
    with _abuse_lock:
        cache = _abuse_cache()
        cache.setdefault("items", {})[ip] = {"ts": time.time(), "data": data}
        _abuse_save(cache)
    return dict(data, configured=True, cached=False)


PROFILE_TYPE = "ip_profile"
PROFILE_SOURCE_PREFIX = "IP画像·"


def profile_rows() -> list[tuple]:
    """按本地缓存生成 (type, value, ip_only, source, malware)；同一 IP/网段多源时合并标签。"""
    labels: dict[str, list[str]] = {}
    raw_cache: dict[str, bytes | None] = {}
    for name, dl_key, parser, kind, label, flag, provider in FEEDS:
        if dl_key not in raw_cache:
            p = _path(dl_key)
            raw_cache[dl_key] = open(p, "rb").read() if os.path.isfile(p) else None
        raw = raw_cache[dl_key]
        if not raw:
            continue
        try:
            items = _PARSERS[parser](raw)
        except Exception:
            continue
        tag = label.replace(" · ", "·")
        for item in items:
            try:
                net = ipaddress.ip_network(item if "/" in item else item + "/32", strict=False)
            except ValueError:
                continue
            if net.version != 4:
                continue
            value = str(net.network_address) if net.prefixlen == 32 else str(net)
            bucket = labels.setdefault(value, [])
            if tag not in bucket:
                bucket.append(tag)
    for ip, svc in STATIC_INFRA:
        bucket = labels.setdefault(ip, [])
        tag = "公共DNS·" + svc
        if tag not in bucket:
            bucket.append(tag)
    rows = []
    for value, tags in labels.items():
        ip_only = value if "/" not in value else ""
        rows.append((PROFILE_TYPE, value, ip_only, (PROFILE_SOURCE_PREFIX + "/".join(tags))[:200], ""))
    return rows


def sync_to_db(db_path: str = "") -> int:
    """把画像整体同步进主库：先删旧的 ip_profile 行再写入，列表里下线的 Tor/代理随之移除。
    用独立 type，不占 (type, value) 唯一键，之后 ThreatFox 等写同一 IP 的恶意记录不受影响。"""
    from export_to_db import connect_db, resolve_db_path, _ensure_schema
    path = resolve_db_path(db_path)
    rows = profile_rows()
    if not rows:
        print("  [SKIP] 本地没有画像缓存，先跑 --update")
        return 0
    conn = connect_db(path)
    cur = conn.cursor()
    _ensure_schema(cur)
    before = cur.execute("SELECT COUNT(*) FROM ioc_records").fetchone()[0]
    t0 = datetime.now().isoformat()
    cur.execute("DELETE FROM ioc_records WHERE type = ?", (PROFILE_TYPE,))
    removed = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    cur.executemany(
        "INSERT OR IGNORE INTO ioc_records (type, value, ip_only, source, malware) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    after = cur.execute("SELECT COUNT(*) FROM ioc_records").fetchone()[0]
    cur.execute(
        """INSERT INTO crawl_logs (source_url, start_time, end_time, status, iocs_found)
           VALUES (?, ?, ?, ?, ?)""",
        ("hunti_ip_profile", t0, datetime.now().isoformat(), "success", len(rows)),
    )
    conn.commit()
    try:
        cur.execute("PRAGMA wal_checkpoint(PASSIVE)")
    except Exception:
        pass
    conn.close()
    net_new = max(0, after - before)
    print("  DB: {}".format(path))
    print("  画像同步: 移除旧 {}  写入 {}（type={}）".format(removed, len(rows), PROFILE_TYPE))
    print("  待写入: {}  新入库: {}  已存在跳过: 0  库总量: {} → {}".format(len(rows), net_new, before, after))
    return len(rows)


def status() -> dict[str, Any]:
    files = {}
    for key in DOWNLOADS:
        p = _path(key)
        files[key] = ({"bytes": os.path.getsize(p),
                       "mtime": datetime.fromtimestamp(os.path.getmtime(p), tz=timezone.utc).isoformat()}
                      if os.path.isfile(p) else None)
    cache = _abuse_cache()
    return {
        "data_dir": DATA_DIR,
        "updated_at": _load_meta().get("updated_at"),
        "downloads": files,
        "index_size": len(get_index()),
        "abuseipdb": {"configured": bool(load_abuseipdb_key()),
                      "cached": len(cache.get("items", {})), "quota": cache.get("quota", {})},
    }


def main():
    ap = argparse.ArgumentParser(description="IP 画像富化（DROP/Tor/CDN/云/VPN/代理）")
    ap.add_argument("--update", action="store_true", help="下载/刷新列表")
    ap.add_argument("--force", action="store_true", help="忽略新鲜度强制重下")
    ap.add_argument("--lookup", metavar="IP", help="查询单个 IP 的画像")
    ap.add_argument("--abuseipdb", metavar="IP", help="实时查 AbuseIPDB")
    ap.add_argument("--status", action="store_true", help="显示本地缓存状态")
    ap.add_argument("--to-db", action="store_true", help="把画像同步进主库（type=ip_profile）")
    ap.add_argument("--db", default="", help="写入的 sqlite 路径（默认 config.ini）")
    args = ap.parse_args()

    if args.update or args.to_db:
        print("=" * 60)
        print("  IP 画像源 →", DATA_DIR)
        print("=" * 60)
        code = 0
        if args.update:
            stats = update_feeds(force=args.force)
            get_index()
            print(f"  下载成功 {len(stats['ok'])}  未过期跳过 {len(stats['skip'])}  失败 {len(stats['fail'])}")
            for f in stats["fail"]:
                print(f"  [FAIL] {f['name']}: {f['error']}")
            # 部分失败保留旧文件，不让 run_all 整步标红
            code = 0 if len(stats["fail"]) < len(DOWNLOADS) else 1
        if args.to_db:
            sync_to_db(args.db)
        return code
    if args.lookup:
        print(json.dumps(lookup(args.lookup.strip()), ensure_ascii=False, indent=2))
        return 0
    if args.abuseipdb:
        print(json.dumps(abuseipdb_check(args.abuseipdb.strip()), ensure_ascii=False, indent=2))
        return 0
    if args.status:
        print(json.dumps(status(), ensure_ascii=False, indent=2))
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
