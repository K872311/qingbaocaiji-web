"""
ThreatCluster 情报采集

- 公开 IOC JSON：高置信 IP / 域名（近 30 天）
- 公开 MISP：事件 + hashes.csv
- 公开暗网受害者：只作情报，不把受害公司域名当 IOC
- 公开 RSS：cluster / 漏洞 / 利用 / 暗网（rss_intel_monitor）
- 认证 MISP（可选）：Settings 里的 tc_live_ Key，请求头 X-API-Key。
  旧 tc_feed_ 查询参数已失效，会 401。

Token 放 config/tc_feed_token.txt 或环境变量 TC_FEED_TOKEN / TC_KEY，不要写进源码。
采集后默认写入 config.ini 的 ioc_db_path（留空则 output/ioc_data.db，可用 --db 覆盖）。
"""
import argparse
import glob
import json
import os
from datetime import datetime

import requests
from crawler_utils import (
    BASE_DIR,
    load_state,
    mark_many_seen,
    save_delta,
    save_state,
    fingerprint,
    load_tc_feed_token,
    is_valid_ip,
    is_valid_domain,
    is_valid_hash,
)
from export_to_db import resolve_db_path, write_iocs

OUTPUT_DIR = os.path.join(BASE_DIR, "output")
INTEL_DIR = os.path.join(OUTPUT_DIR, "intel")
IOC_DIR = os.path.join(OUTPUT_DIR, "iocs")
os.makedirs(INTEL_DIR, exist_ok=True)
os.makedirs(IOC_DIR, exist_ok=True)

PUBLIC_IOC_JSON = "https://threatcluster.io/api/iocs/public/feed.json"
PUBLIC_MANIFEST = "https://threatcluster.io/misp/manifest.json"
PUBLIC_EVENT = "https://threatcluster.io/misp/{uuid}.json"
PUBLIC_HASHES = "https://threatcluster.io/misp/hashes.csv"
DARKWEB_VICTIMS = "https://threatcluster.io/api/darkweb/public/victims.json"
AUTH_MANIFEST = "https://threatcluster.io/api/misp/manifest.json"
AUTH_EVENT = "https://threatcluster.io/api/misp/{uuid}.json"

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HuntiIOC/1.0"}
MODULE = "threatcluster"

_TYPE_MAP = {
    "ipv4": "ip",
    "ipv6": "ip",
    "ip": "ip",
    "ip-src": "ip",
    "ip-dst": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
}

session = requests.Session()
session.headers.update(HEADERS)


def _get(url, params=None, extra_headers=None):
    r = session.get(url, params=params, headers=extra_headers or {}, timeout=30)
    r.raise_for_status()
    return r


def _live_api_key(token):
    """旧 tc_feed_ 查询 token 已失效；只有 tc_live_ 这类 Key 走 X-API-Key。"""
    t = (token or "").strip()
    if not t or t.startswith("tc_feed_"):
        return ""
    return t


def _map_type(raw):
    return _TYPE_MAP.get((raw or "").lower())


def _source_url(item):
    sources = item.get("sources") or []
    if sources and isinstance(sources[0], dict):
        return sources[0].get("url") or ""
    return item.get("url") or ""


def _valid(ioc_type, value):
    if ioc_type == "ip":
        return is_valid_ip(value)
    if ioc_type == "domain":
        return is_valid_domain(value, exclude_substrings=("threatcluster.io",))
    if ioc_type in ("md5", "sha1", "sha256"):
        return is_valid_hash(ioc_type, value)
    if ioc_type == "url":
        if "threatcluster.io" in value.lower():
            return False
        return value.startswith("http")
    return False


def _tags_to_actors(tags):
    actors = []
    for tag in tags or []:
        if isinstance(tag, dict):
            kind = (tag.get("type") or "").lower()
            val = (tag.get("value") or tag.get("name") or "").strip()
            if val and kind in ("threat-actor", "campaign", "apt", "group", "malware"):
                actors.append(val)
        elif tag:
            actors.append(str(tag).strip())
    return list(dict.fromkeys(a for a in actors if a))


def fetch_public_iocs():
    data = _get(PUBLIC_IOC_JSON).json()
    rows = []
    for item in data.get("iocs") or []:
        ioc_type = _map_type(item.get("type"))
        value = (item.get("value") or "").strip()
        if not ioc_type or not value or not _valid(ioc_type, value):
            continue
        rows.append({
            "source": "ThreatCluster",
            "url": _source_url(item),
            "title": (item.get("reason") or "")[:160],
            "ioc_type": ioc_type,
            "ioc_value": value,
            "threat_actors": _tags_to_actors(item.get("tags") or []),
            "malware": [],
            "confidence": item.get("confidence", ""),
            "crawl_time": datetime.now().isoformat(),
        })
    return rows, data.get("generated_at", "")


def fetch_misp_events(token=""):
    api_key = _live_api_key(token)
    if token and not api_key:
        print("  旧 Feed Token（tc_feed_）已失效，改用公开 MISP")
    headers = {"X-API-Key": api_key} if api_key else {}
    manifest_url = AUTH_MANIFEST if api_key else PUBLIC_MANIFEST
    event_tpl = AUTH_EVENT if api_key else PUBLIC_EVENT
    try:
        manifest = _get(manifest_url, extra_headers=headers).json()
    except Exception as e:
        if api_key:
            print("  认证 MISP 失败，回退公开清单:", e)
            headers = {}
            event_tpl = PUBLIC_EVENT
            manifest = _get(PUBLIC_MANIFEST).json()
        else:
            raise
    events = []
    iocs = []
    for uuid, meta in (manifest or {}).items():
        if not isinstance(meta, dict):
            continue
        try:
            ev = _get(event_tpl.format(uuid=uuid), extra_headers=headers).json().get("Event") or {}
        except Exception:
            continue
        title = ev.get("info") or meta.get("info") or uuid
        attrs = ev.get("Attribute") or []
        tags = [t.get("name", "") for t in (ev.get("Tag") or []) if t.get("name")]
        actors = [t.split(":", 1)[-1] for t in tags if t.startswith("misp-galaxy:threat-actor")]
        for a in attrs:
            if a.get("type") == "threat-actor" and a.get("value"):
                actors.append(a["value"])
        malware = [a.get("value") for a in attrs if a.get("type") == "malware-type" and a.get("value")]
        link = ""
        for a in attrs:
            if a.get("type") == "link" and str(a.get("value", "")).startswith("http"):
                if "threatcluster.io" not in a["value"]:
                    link = a["value"]
                    break
        if not link:
            link = "https://threatcluster.io/cluster/" + uuid
        events.append({
            "title": title,
            "url": link,
            "source": "ThreatCluster",
            "published": ev.get("date") or "",
            "threat_actors": sorted(set(actors)),
            "malware": sorted(set(malware)),
            "content": "\n".join(
                a.get("value", "") for a in attrs if a.get("type") == "text" and a.get("value")
            )[:8000],
            "crawl_time": datetime.now().isoformat(),
        })
        for a in attrs:
            ioc_type = _map_type(a.get("type"))
            value = (a.get("value") or "").strip()
            if "|" in value and ioc_type in ("md5", "sha1", "sha256"):
                value = value.split("|")[-1].strip()
            if not ioc_type or not value or not _valid(ioc_type, value):
                continue
            iocs.append({
                "source": "ThreatCluster",
                "url": link,
                "title": title,
                "ioc_type": ioc_type,
                "ioc_value": value,
                "threat_actors": sorted(set(actors)),
                "malware": sorted(set(malware)),
                "confidence": "misp",
                "crawl_time": datetime.now().isoformat(),
            })
    return events, iocs


def _hash_type(value):
    n = len(value or "")
    if n == 32:
        return "md5"
    if n == 40:
        return "sha1"
    if n == 64:
        return "sha256"
    return ""


def fetch_misp_hashes():
    text = _get(PUBLIC_HASHES).text
    rows = []
    for line in text.splitlines():
        line = (line or "").strip()
        if not line or line.startswith("#") or line.lower().startswith("hash"):
            continue
        parts = [p.strip() for p in line.split(",")]
        value = (parts[0] or "").lower()
        uuid = parts[1] if len(parts) > 1 else ""
        ioc_type = _hash_type(value)
        if not ioc_type or not is_valid_hash(ioc_type, value):
            continue
        rows.append({
            "source": "ThreatCluster",
            "url": PUBLIC_EVENT.format(uuid=uuid) if uuid else "https://threatcluster.io/misp/hashes.csv",
            "title": "ThreatCluster MISP hash",
            "ioc_type": ioc_type,
            "ioc_value": value,
            "threat_actors": [],
            "malware": [],
            "confidence": "misp",
            "crawl_time": datetime.now().isoformat(),
        })
    return rows


def fetch_darkweb_victims():
    """受害公司不是 IOC，只落情报事件。"""
    data = _get(DARKWEB_VICTIMS, extra_headers={"Accept": "application/json"}).json()
    events = []
    for item in data.get("victims") or []:
        if not isinstance(item, dict):
            continue
        victim = (item.get("victim") or "").strip()
        group = (item.get("group") or "").strip()
        if not victim:
            continue
        discovered = (item.get("discovered") or "")[:32]
        slug = "{}|{}|{}".format(group.lower(), victim.lower(), discovered)
        events.append({
            "title": "{} claimed by {}".format(victim, group or "unknown"),
            "url": "https://threatcluster.io/dark-web#" + slug.replace(" ", "-"),
            "source": "ThreatCluster",
            "published": discovered,
            "threat_actors": [group] if group else [],
            "malware": [group] if group else [],
            "country": item.get("country") or "",
            "sector": item.get("sector") or "",
            "content": "victim={} group={} country={} sector={} status={}".format(
                victim, group, item.get("country") or "",
                item.get("sector") or "", item.get("status") or "",
            ),
            "crawl_time": datetime.now().isoformat(),
        })
    return events


def load_saved_tc_iocs():
    items = []
    seen = set()
    history_dir = os.path.join(OUTPUT_DIR, "history", MODULE)
    paths = sorted(glob.glob(os.path.join(IOC_DIR, "tc_iocs_*.json")))
    paths.extend(sorted(glob.glob(os.path.join(history_dir, "iocs_*.json"))))
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, list):
            continue
        for row in data:
            key = "{}|{}".format(row.get("ioc_type", ""), (row.get("ioc_value") or "").lower())
            if key in seen:
                continue
            seen.add(key)
            items.append(row)
    return items


def main():
    parser = argparse.ArgumentParser(description="ThreatCluster 情报采集")
    parser.add_argument("--db", default="", help="写入的 sqlite 路径（默认 config.ini 的 ioc_db_path）")
    parser.add_argument("--no-db", action="store_true", help="只采集，不写数据库")
    args = parser.parse_args()
    db_path = resolve_db_path(args.db)

    print("=" * 60)
    print("  ThreatCluster 情报采集")
    print("=" * 60)
    token = load_tc_feed_token()
    print("  Feed Token:", "已配置" if token else "未配置（只用公开 IOC / 公开 MISP）")
    print("  写入库:", db_path)

    state = load_state(MODULE)
    seen = state.setdefault("seen_fingerprints", {})

    public_iocs, generated = fetch_public_iocs()
    print("  公开 IOC JSON: {} 条 ({})".format(len(public_iocs), generated or "-"))

    events, misp_iocs = [], []
    try:
        events, misp_iocs = fetch_misp_events(token)
        print("  MISP 事件: {} 篇, IOC {} 条".format(len(events), len(misp_iocs)))
    except Exception as e:
        print("  MISP 失败（公开 IOC 仍入库）:", e)

    hash_iocs = []
    try:
        hash_iocs = fetch_misp_hashes()
        print("  MISP hashes.csv: {} 条".format(len(hash_iocs)))
    except Exception as e:
        print("  hashes.csv 失败:", e)

    try:
        dw_events = fetch_darkweb_victims()
        print("  暗网受害者: {} 条（只作情报，不当 IOC）".format(len(dw_events)))
        events.extend(dw_events)
    except Exception as e:
        print("  暗网受害者失败:", e)

    new_iocs = []
    new_fps = []
    for row in public_iocs + misp_iocs + hash_iocs:
        fp = fingerprint(row["ioc_type"], row["ioc_value"])
        if fp in seen:
            continue
        seen[fp] = {"seen_at": datetime.now().isoformat(), "url": row.get("url", "")}
        new_iocs.append(row)
        new_fps.append(fp)

    new_events = []
    for ev in events:
        fp = fingerprint("event", ev.get("url") or ev.get("title"))
        if fp in seen:
            continue
        seen[fp] = {"seen_at": datetime.now().isoformat(), "url": ev.get("url", "")}
        new_events.append(ev)
        new_fps.append(fp)

    if new_fps:
        mark_many_seen(MODULE, new_fps)
    else:
        save_state(MODULE, state)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if new_events:
        intel_path = os.path.join(INTEL_DIR, "tc_intel_{}.json".format(ts))
        with open(intel_path, "w", encoding="utf-8") as f:
            json.dump(new_events, f, ensure_ascii=False, indent=2)
        print("  新事件:", intel_path)
    if new_iocs:
        ioc_path = os.path.join(IOC_DIR, "tc_iocs_{}.json".format(ts))
        with open(ioc_path, "w", encoding="utf-8") as f:
            json.dump(new_iocs, f, ensure_ascii=False, indent=2)
        save_delta(MODULE, new_iocs, prefix="iocs")
        print("  新 IOC:", ioc_path)
        counts = {}
        for r in new_iocs:
            counts[r["ioc_type"]] = counts.get(r["ioc_type"], 0) + 1
        print("  类型:", ", ".join("{}={}".format(k, v) for k, v in sorted(counts.items())))
    else:
        print("  无新增 IOC（增量已采过，仍会同步写入数据库）")
    print("  本轮新增 IOC: {}".format(len(new_iocs)))
    if not args.no_db:
        to_write = []
        seen_k = set()
        for row in new_iocs + public_iocs + misp_iocs + hash_iocs + load_saved_tc_iocs():
            key = "{}|{}".format(row.get("ioc_type", ""), (row.get("ioc_value") or "").lower())
            if key in seen_k:
                continue
            seen_k.add(key)
            to_write.append(row)
        write_iocs(
            to_write,
            db_path,
            source="ThreatCluster",
            log_url="https://threatcluster.io/",
        )
    return new_iocs


if __name__ == "__main__":
    main()
