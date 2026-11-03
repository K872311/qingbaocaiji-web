"""
MISP Default Feeds 采集

页面：https://www.misp-project.org/feeds/
清单：MISP defaults.json（优先 jsDelivr，GitHub raw 作备份）

默认采集官方清单里的公开源（域名 / URL / 哈希；默认不收 IP）。
EXTRA_FEEDS 里显式加入的封锁/钓鱼源可按源放开 IP。
MalwareBazaar MISP 目录按 manifest.json 全量拉，按事件 UUID+timestamp 断点续跑，
之后每天只补新日期。跳过 Tor、比特币、ThreatFox，以及 IPsum / dataplane 等聚合噪音源。
"""
import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urljoin

import requests
from crawler_utils import (
    BASE_DIR,
    extract_iocs,
    fingerprint,
    is_valid_domain,
    is_valid_hash,
    is_valid_ip,
    load_state,
    mark_many_seen,
    save_delta,
    save_state,
)
from export_to_db import resolve_db_path, write_iocs

OUTPUT_DIR = os.path.join(BASE_DIR, "output")
IOC_DIR = os.path.join(OUTPUT_DIR, "iocs")
os.makedirs(IOC_DIR, exist_ok=True)

DEFAULTS_URLS = (
    "https://cdn.jsdelivr.net/gh/MISP/MISP@2.5/app/files/feed-metadata/defaults.json",
    "https://raw.githubusercontent.com/MISP/MISP/2.5/app/files/feed-metadata/defaults.json",
)
MODULE = "misp_feeds"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HuntiIOC/1.0"}
# MISP 目录源每轮每源最多拉多少个新事件（新的优先），积压留给下一轮
MISP_EVENTS_PER_RUN = 100
# 早于 N 天的事件不拉（CIRCL 等清单里有 2014 年的老事件）；0 = 不限
MISP_MAX_AGE_DAYS = 365
MISP_EVENTS_MODULE = "misp_events"
MAX_BYTES = 40 * 1024 * 1024
BAZAAR_MAX_BYTES = 64 * 1024 * 1024
BAZAAR_MISP_URL = "https://bazaar.abuse.ch/downloads/misp/"

# 排除：Tor、比特币、ThreatFox（独立脚本）、以及纯 IP 黑名单源
SKIP_KEYS = (
    "tor ", "torlist", "tor all", "tor exit",
    "bitcoin",
    "threatfox",
    # Rösti：把各家博客 RSS 二次打包，和 rss_intel_monitor 重复，用户不要
    "rosti.dev",
    "ipsum",
    "dataplane",
    "blocklist.de",
    "dshield",
    "feodo",
    "bruteforce",
    "brute force",
    "ciarmy",
    "cinsscore",
    "greensnow",
    "sslbl",
    "ip_list",
    "iplist",
    "ip list",
    "ip block",
    "compromised ips",
)

SKIP_IOC_TYPES = {"ip", "ipv4", "ipv6", "ip:port"}

# ThreatFox 已有独立脚本；URLhaus MISP 目录极大且已有 csv_recent
SKIP_URL_PARTS = (
    "threatfox.abuse.ch",
    "urlhaus.abuse.ch/downloads/misp",
    "dan.me.uk/torlist",
)

# 页面有、或 defaults 里被 SKIP 掉、需要手工放开的源。
# allow_ip=True：仅该源收 IP（默认清单仍不收 IP，避免 IPsum 类灌库）。
# EXTRA 不走 _wanted，避免被 SKIP_KEYS 误杀。
EXTRA_FEEDS = (
    {
        "name": "MalwareBazaar",
        "url": BAZAAR_MISP_URL,
        "source_format": "misp",
    },
    # --- 可用直连源（2026-10 探测）---
    {
        "name": "Binary Defense Banlist",
        "url": "https://www.binarydefense.com/banlist.txt",
        "source_format": "freetext",
        "allow_ip": True,
    },
    {
        "name": "blocklist.de",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "source_format": "freetext",
        "allow_ip": True,
    },
    {
        "name": "CINS Score",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "source_format": "freetext",
        "allow_ip": True,
    },
    {
        "name": "BruteForceBlocker",
        "url": "https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
        "source_format": "freetext",
        "allow_ip": True,
    },
    {
        "name": "Emerging Threats Compromised",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "source_format": "freetext",
        "allow_ip": True,
    },
    # 钓鱼域名 JSON 数组；拼写修正自 phish.sinking.tachts
    {
        "name": "Sinking Yachts Phish",
        "url": "https://phish.sinking.yachts/v2/all",
        "source_format": "json_domains",
    },
)

session = requests.Session()
session.headers.update(HEADERS)


def _log(*args):
    print(*args, flush=True)


def _wanted(name, url):
    blob = "{} {}".format(name or "", url or "").lower()
    if any(k in blob for k in SKIP_KEYS):
        return False
    if any(p in blob for p in SKIP_URL_PARTS):
        return False
    return True


def _guess_type(value):
    v = (value or "").strip().strip('"').strip("'")
    if not v or v.startswith("#"):
        return None, ""
    if v.startswith("http://") or v.startswith("https://"):
        return "url", v
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$", v):
        return "ip", v
    low = v.lower()
    if is_valid_hash("md5", low):
        return "md5", low
    if is_valid_hash("sha1", low):
        return "sha1", low
    if is_valid_hash("sha256", low):
        return "sha256", low
    if is_valid_domain(v):
        return "domain", v.lower()
    return None, ""


def _valid(ioc_type, value):
    if ioc_type == "ip":
        return is_valid_ip(value)
    if ioc_type == "domain":
        return is_valid_domain(value)
    if ioc_type in ("md5", "sha1", "sha256"):
        return is_valid_hash(ioc_type, value)
    if ioc_type == "url":
        return value.startswith("http")
    return False


def _row(source, url, ioc_type, value, malware="", allow_ip=False):
    if ioc_type in SKIP_IOC_TYPES and not allow_ip:
        return None
    if not ioc_type or not value or not _valid(ioc_type, value):
        return None
    return {
        "source": source,
        "url": url,
        "title": source,
        "ioc_type": ioc_type,
        "ioc_value": value,
        "threat_actors": [],
        "malware": [malware] if malware else [],
        "crawl_time": datetime.now().isoformat(),
    }


def _from_text(text, source, url, allow_ip=False):
    rows = []
    seen = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # danger.rulez 等：首列 IP，后面跟计数/日期
        head = line.split(",")[0].split(";")[0].split()[0].split("\t")[0]
        found = extract_iocs(head if allow_ip else line)
        typed = []
        for kind, values in found.items():
            for val in values:
                typed.append((kind, val))
        if not typed:
            kind, val = _guess_type(head)
            if kind:
                typed.append((kind, val))
        for kind, val in typed:
            key = "{}|{}".format(kind, val.lower())
            if key in seen:
                continue
            seen.add(key)
            row = _row(source, url, kind, val, allow_ip=allow_ip)
            if row:
                rows.append(row)
    return rows


def _download(url, timeout=40, max_bytes=MAX_BYTES):
    with session.get(url, timeout=timeout, stream=True) as r:
        r.raise_for_status()
        chunks = []
        n = 0
        for chunk in r.iter_content(65536):
            if not chunk:
                continue
            n += len(chunk)
            if n > max_bytes:
                raise RuntimeError("超过 {}MB，跳过".format(max_bytes // 1024 // 1024))
            chunks.append(chunk)
        raw = b"".join(chunks)
        enc = r.encoding or "utf-8"
        return raw.decode(enc, errors="replace")


def fetch_defaults():
    last = None
    for url in DEFAULTS_URLS:
        try:
            _log("  拉取清单:", url)
            r = session.get(url, timeout=30)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, list) and data:
                return data
        except Exception as e:
            last = e
            _log("    [清单失败]", e)
    raise last or RuntimeError("无法获取 MISP defaults.json")


def fetch_simple(feed):
    url = feed.get("url") or ""
    name = feed.get("name") or "MISP feed"
    source = "MISP: {}".format(name)[:80]
    allow_ip = bool(feed.get("allow_ip"))
    fmt = (feed.get("source_format") or "").lower()
    if fmt == "json_domains":
        return fetch_json_domains(feed)
    text = _download(url)
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            data = json.loads(text)
            if isinstance(data, list) and data and isinstance(data[0], str):
                return _rows_from_domain_list(data, source, url)
            blob = json.dumps(data, ensure_ascii=False)
            return _from_text(blob, source, url, allow_ip=allow_ip)
        except Exception:
            pass
    return _from_text(text, source, url, allow_ip=allow_ip)


def _rows_from_domain_list(items, source, url):
    rows = []
    seen = set()
    for raw in items or []:
        val = str(raw or "").strip().lower().rstrip(".")
        if not val or val in seen:
            continue
        seen.add(val)
        row = _row(source, url, "domain", val)
        if row:
            rows.append(row)
    return rows


def fetch_json_domains(feed):
    """Sinking Yachts 等：GET 返回 JSON 字符串数组。"""
    url = feed.get("url") or ""
    name = feed.get("name") or "domain feed"
    source = "MISP: {}".format(name)[:80]
    text = _download(url, timeout=60)
    data = json.loads(text)
    if not isinstance(data, list):
        raise RuntimeError("期望 JSON 数组，实际 {}".format(type(data).__name__))
    return _rows_from_domain_list(data, source, url)


def fetch_misp_dir(feed, ev_state):
    """manifest.json 不按时间排序：按 timestamp 倒序增量拉，已拉过且没更新的事件跳过。"""
    base = (feed.get("url") or "").rstrip("/") + "/"
    name = feed.get("name") or "MISP"
    source = "MISP: {}".format(name)[:80]
    try:
        manifest = session.get(urljoin(base, "manifest.json"), timeout=60).json()
    except Exception as e:
        _log("    [manifest 失败] {}".format(e))
        return []
    if not isinstance(manifest, dict):
        return []
    done = ev_state.setdefault(base, {})
    cutoff = time.time() - MISP_MAX_AGE_DAYS * 86400 if MISP_MAX_AGE_DAYS else 0
    todo = []
    for uuid, meta in manifest.items():
        meta = meta or {}
        try:
            ts = int(meta.get("timestamp") or 0)
        except (TypeError, ValueError):
            ts = 0
        if cutoff and ts and ts < cutoff:
            continue
        if done.get(uuid, -1) >= ts:
            continue
        todo.append((ts, uuid, meta))
    todo.sort(reverse=True)
    _log("    清单事件: {}  待拉: {}  本轮上限: {}".format(len(manifest), len(todo), MISP_EVENTS_PER_RUN))
    rows = []
    for ts, uuid, meta in todo[:MISP_EVENTS_PER_RUN]:
        ev_url = urljoin(base, "{}.json".format(uuid))
        try:
            ev = json.loads(_download(ev_url, timeout=40))
        except Exception:
            continue
        event = ev.get("Event") or ev
        title = event.get("info") or meta.get("info") or name
        rows.extend(_rows_from_misp_event(event, source, ev_url, title))
        done[uuid] = ts
    return rows


def _is_bazaar_misp(feed):
    return "bazaar.abuse.ch/downloads/misp" in (feed.get("url") or "").lower()


def _malware_hint(attr, event):
    for tag in list(attr.get("Tag") or []) + list(event.get("Tag") or []):
        name = ""
        if isinstance(tag, dict):
            name = tag.get("name") or ""
        else:
            name = str(tag)
        low = name.lower()
        if "malpedia=" in low:
            return name.split("=", 1)[-1].strip().strip('"')[:200]
        if low.startswith("malware:"):
            return name.split(":", 1)[-1].strip()[:200]
    return ""


def _rows_from_misp_event(event, source, url, title=""):
    attrs = list(event.get("Attribute") or [])
    for obj in event.get("Object") or []:
        attrs.extend(obj.get("Attribute") or [])
    mapped_types = {
        "ip-src": "ip", "ip-dst": "ip", "ip": "ip",
        "domain": "domain", "hostname": "domain",
        "url": "url", "uri": "url",
        "md5": "md5", "sha1": "sha1", "sha256": "sha256",
        "filename|md5": "md5", "filename|sha1": "sha1", "filename|sha256": "sha256",
        "malware-sample": "md5",
    }
    rows = []
    seen = set()
    for a in attrs:
        raw_type = (a.get("type") or "").lower()
        value = str(a.get("value") or "").strip()
        mapped = mapped_types.get(raw_type)
        if "|" in value and mapped in ("md5", "sha1", "sha256"):
            value = value.split("|")[-1].strip()
        row = _row(source, url, mapped, value, _malware_hint(a, event))
        if not row:
            continue
        key = "{}|{}".format(row["ioc_type"], row["ioc_value"].lower())
        if key in seen:
            continue
        seen.add(key)
        if title:
            row["title"] = title[:160]
        rows.append(row)
    return rows


def fetch_bazaar_misp(feed, state, db_path, no_db=False):
    """按 manifest.json 全量/增量拉 MalwareBazaar MISP 目录，按事件断点续跑。"""
    base = (feed.get("url") or BAZAAR_MISP_URL).rstrip("/") + "/"
    _log("  MalwareBazaar MISP:", base + "manifest.json")
    manifest = session.get(urljoin(base, "manifest.json"), timeout=60).json()
    if not isinstance(manifest, dict):
        _log("    [跳过] manifest 不是对象")
        return [], 0

    bz_state = load_state("misp_bazaar")
    done = bz_state.setdefault("bazaar_misp_events", {})
    items = []
    for uuid, meta in manifest.items():
        meta = meta or {}
        ts = int(meta.get("timestamp") or 0)
        prev = done.get(uuid) or {}
        if prev.get("timestamp", -1) >= ts and prev.get("ok"):
            continue
        items.append((meta.get("date") or "", ts, uuid, meta))
    items.sort()
    _log("    清单事件: {}  待拉: {}".format(len(manifest), len(items)))

    pulled = 0
    inserted = 0
    for i, (date, ts, uuid, meta) in enumerate(items, 1):
        ev_url = urljoin(base, "{}.json".format(uuid))
        try:
            text = _download(ev_url, timeout=90, max_bytes=BAZAAR_MAX_BYTES)
            ev = json.loads(text)
            event = ev.get("Event") or ev
            title = event.get("info") or meta.get("info") or "MalwareBazaar"
            rows = _rows_from_misp_event(event, "MalwareBazaar", ev_url, title)
            n = 0
            if rows and not no_db:
                n = write_iocs(
                    rows, db_path, source="MalwareBazaar",
                    log_url=ev_url, quiet=True,
                )
            done[uuid] = {
                "timestamp": ts,
                "date": date,
                "ok": True,
                "iocs": len(rows),
                "inserted": n,
            }
            save_state("misp_bazaar", bz_state)
            pulled += len(rows)
            inserted += n
            if i == 1 or i % 5 == 0 or i == len(items):
                _log("    [{}/{}] {}  IOC={}  新入库={}".format(
                    i, len(items), date or uuid[:8], len(rows), n,
                ))
        except Exception as e:
            _log("    [{}/{}] {} 失败: {}".format(i, len(items), date or uuid[:8], e))
            continue
    save_state("misp_bazaar", bz_state)
    _log("    Bazaar MISP 本轮 IOC: {}  新入库: {}".format(pulled, inserted))
    return [], inserted


def main():
    parser = argparse.ArgumentParser(description="MISP Default Feeds 采集")
    parser.add_argument("--db", default="", help="写入的 sqlite 路径")
    parser.add_argument("--no-db", action="store_true", help="只采集，不写数据库")
    parser.add_argument("--bazaar-only", action="store_true",
                        help="只拉 MalwareBazaar MISP 目录（manifest 全量/增量）")
    parser.add_argument("--extras-only", action="store_true",
                        help="只采 EXTRA_FEEDS（封锁名单 / 钓鱼域名等手工源）")
    args = parser.parse_args()
    db_path = resolve_db_path(args.db)

    _log("=" * 60)
    _log("  MISP Default Feeds 采集")
    _log("  https://www.misp-project.org/feeds/")
    _log("=" * 60)
    _log("  写入库:", db_path)

    catalog = []
    feeds = []
    seen_urls = set()
    if not args.extras_only:
        catalog = fetch_defaults()
        for item in catalog:
            feed = item.get("Feed") or item
            url = (feed.get("url") or "").rstrip("/")
            if url in seen_urls:
                continue
            if _wanted(feed.get("name"), feed.get("url")):
                feeds.append(feed)
                seen_urls.add(url)
    for extra in EXTRA_FEEDS:
        if args.extras_only and _is_bazaar_misp(extra):
            continue
        url = (extra.get("url") or "").rstrip("/")
        if url in seen_urls:
            continue
        # EXTRA 显式名单，不走 _wanted（否则 allow_ip 源会被 SKIP_KEYS 挡掉）
        feeds.append(dict(extra))
        seen_urls.add(url)
    if args.bazaar_only:
        feeds = [f for f in feeds if _is_bazaar_misp(f)]
        if not feeds:
            feeds = [{"name": "MalwareBazaar", "url": BAZAAR_MISP_URL, "source_format": "misp"}]
    _log("  清单: {} 条, 选用: {} 条{}".format(
        len(catalog), len(feeds), "  [--extras-only]" if args.extras_only else "",
    ))

    state = load_state(MODULE)
    seen = state.setdefault("seen_fingerprints", {})
    ev_state = load_state(MISP_EVENTS_MODULE)
    ev_done = ev_state.setdefault("events", {})
    all_rows = []
    new_iocs = []
    new_fps = []

    for i, feed in enumerate(feeds, 1):
        name = feed.get("name") or ""
        fmt = (feed.get("source_format") or "").lower()
        _log("  [{}/{}] {} ...".format(i, len(feeds), name[:52]))
        try:
            if _is_bazaar_misp(feed):
                fetch_bazaar_misp(feed, state, db_path, no_db=args.no_db)
                continue
            if fmt == "misp":
                rows = fetch_misp_dir(feed, ev_done)
            else:
                rows = fetch_simple(feed)
        except Exception as e:
            _log("    [跳过] {}".format(e))
            continue
        _log("    {} 条".format(len(rows)))
        all_rows.extend(rows)
        for row in rows:
            fp = fingerprint(row["ioc_type"], row["ioc_value"], row.get("source", ""))
            if fp in seen:
                continue
            seen[fp] = {"seen_at": datetime.now().isoformat()}
            new_iocs.append(row)
            new_fps.append(fp)

    if new_fps:
        mark_many_seen(MODULE, new_fps)
    else:
        save_state(MODULE, state)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if new_iocs:
        path = os.path.join(IOC_DIR, "misp_iocs_{}.json".format(ts))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(new_iocs, f, ensure_ascii=False, indent=2)
        save_delta(MODULE, new_iocs, prefix="iocs")
        _log("  新 IOC:", path)
        counts = {}
        for r in new_iocs:
            counts[r["ioc_type"]] = counts.get(r["ioc_type"], 0) + 1
        _log("  类型:", ", ".join("{}={}".format(k, v) for k, v in sorted(counts.items())))
    else:
        _log("  无新增 IOC")
    _log("  本轮拉取: {}  新增: {}".format(len(all_rows), len(new_iocs)))

    # 指纹增量只影响 JSON；入库一律 INSERT OR IGNORE，避免中断后丢数
    if not args.no_db and all_rows:
        # source 留空：沿用每行自带的 "MISP: xxx"，便于面板区分封锁源
        write_iocs(all_rows, db_path, source="",
                   log_url="https://www.misp-project.org/feeds/")
    # 入库后再记事件进度，中途失败下一轮会重拉
    if not args.no_db:
        save_state(MISP_EVENTS_MODULE, ev_state)
    return new_iocs


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    main()
