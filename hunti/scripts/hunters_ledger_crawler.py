"""
The Hunter's Ledger IOC 采集

发现源：https://the-hunters-ledger.com/feed.xml （Atom，指向 /reports/<slug>/）
机器可读：https://the-hunters-ledger.com/ioc-feeds/<slug>-iocs.json
列表页补全 Atom 窗口以外的战役：https://the-hunters-ledger.com/ioc-feeds/

CC BY 4.0，入库 source 写 Hunter's Ledger。
默认只收 HIGH / DEFINITE / CRITICAL，且 action 不是 MONITOR。
默认收 ip / domain / url / md5 / sha1 / sha256。

用法:
  py -X utf8 hunters_ledger_crawler.py
  py -X utf8 hunters_ledger_crawler.py --days 180
  py -X utf8 hunters_ledger_crawler.py --no-db
"""
import argparse
import json
import os
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
from crawler_utils import (
    BASE_DIR,
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

FEED_URL = "https://the-hunters-ledger.com/feed.xml"
LISTING_URL = "https://the-hunters-ledger.com/ioc-feeds/"
REPORT_URL = "https://the-hunters-ledger.com/reports/{}/"
IOC_JSON_URL = "https://the-hunters-ledger.com/ioc-feeds/{}-iocs.json"
SOURCE = "Hunter's Ledger"
MODULE = "hunters_ledger"
ATOM_NS = "{http://www.w3.org/2005/Atom}"

KEEP_CONF = {"high", "definite", "critical", "confirmed"}
SKIP_ACTION = {"monitor", "ignore", "info"}
HASH_TYPES = ("sha256", "md5", "sha1")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HuntiIOC/1.0",
    "Accept": "application/json, application/atom+xml, text/html;q=0.9",
}

session = requests.Session()
session.headers.update(HEADERS)

_SLUG_FEED = re.compile(r"/reports/([A-Za-z0-9._-]+)/?")
_SLUG_LIST = re.compile(r"/ioc-feeds/([A-Za-z0-9._-]+)/?")
_SLUG_JSON = re.compile(r"/ioc-feeds/([A-Za-z0-9._-]+)-iocs\.json")
_IP_SUFFIX = re.compile(r"-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$")


def _log(*args):
    print(*args, flush=True)


def _get(url, timeout=30, retries=3):
    last = None
    for attempt in range(1, retries + 1):
        try:
            r = session.get(url, timeout=timeout)
            r.raise_for_status()
            return r
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last = e
            time.sleep(min(8, attempt * 2))
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                raise
            last = e
            if e.response is not None and e.response.status_code in (429, 502, 503, 504):
                time.sleep(min(12, attempt * 3))
                continue
            raise
    raise last


def _atom_text(el, tag):
    node = el.find(ATOM_NS + tag)
    if node is None:
        node = el.find(tag)
    if node is None or not node.text:
        return ""
    return node.text.strip()


def _parse_dt(value):
    raw = (value or "").strip()
    if not raw:
        return None
    raw = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _slug_from_url(url, pattern):
    m = pattern.search(url or "")
    if not m:
        return ""
    slug = m.group(1).strip()
    if slug.lower() in ("", "ioc-feeds", "stix"):
        return ""
    if slug.lower().endswith("-iocs.json"):
        slug = slug[: -len("-iocs.json")]
    return slug


def discover_campaigns():
    """Atom 给近期战役；列表页补全历史 slug。"""
    campaigns = {}

    r = _get(FEED_URL)
    root = ET.fromstring(r.content)
    for entry in root.findall(ATOM_NS + "entry") or root.findall("entry"):
        link_el = entry.find(ATOM_NS + "link")
        if link_el is None:
            link_el = entry.find("link")
        href = link_el.get("href", "") if link_el is not None else ""
        if not href:
            href = _atom_text(entry, "id")
        slug = _slug_from_url(href, _SLUG_FEED)
        if not slug:
            continue
        title = _atom_text(entry, "title") or slug
        published = _parse_dt(_atom_text(entry, "published") or _atom_text(entry, "updated"))
        campaigns[slug] = {
            "slug": slug,
            "title": title,
            "published": published,
            "report_url": href or REPORT_URL.format(slug),
        }

    listing = _get(LISTING_URL).text
    for match in _SLUG_LIST.finditer(listing):
        slug = match.group(1).strip()
        if not slug or slug.endswith(".json"):
            continue
        campaigns.setdefault(slug, {
            "slug": slug,
            "title": slug,
            "published": None,
            "report_url": REPORT_URL.format(slug),
        })
    for match in _SLUG_JSON.finditer(listing):
        slug = match.group(1).strip()
        if slug:
            campaigns.setdefault(slug, {
                "slug": slug,
                "title": slug,
                "published": None,
                "report_url": REPORT_URL.format(slug),
            })
    return list(campaigns.values())


def _conf(item, fallback=""):
    raw = ""
    if isinstance(item, dict):
        raw = str(item.get("confidence") or "").strip()
    if not raw:
        raw = fallback or ""
    return raw.lower()


def _action(item):
    if not isinstance(item, dict):
        return ""
    return str(item.get("action") or "").strip().lower()


def _keep_item(item, fallback_conf=""):
    if _action(item) in SKIP_ACTION:
        return False
    conf = _conf(item, fallback_conf)
    token = conf.split()[0].strip("(),;") if conf else ""
    if token and token not in KEEP_CONF:
        return False
    if isinstance(item, dict):
        fp = str(item.get("false_positive_risk") or "").strip().lower()
        if fp and fp not in ("low", "none", "n/a"):
            return False
    return True


def _item_value(item, *keys):
    if isinstance(item, str):
        return item.strip()
    if not isinstance(item, dict):
        return ""
    for key in keys:
        val = item.get(key)
        if val is None:
            continue
        text = str(val).strip()
        if text:
            return text
    return ""


def _clean_name(val):
    val = str(val or "").strip()
    if not val:
        return ""
    low = val.lower()
    if low.startswith("multi-family") or low.startswith("multi-actor"):
        return ""
    if low in ("unknown", "n/a", "none"):
        return ""
    if len(val) > 80:
        val = val[:80].rstrip()
    return val


def _malware(meta):
    names = []
    for key in ("malware_name", "family"):
        val = _clean_name((meta or {}).get(key))
        if val and val not in names:
            names.append(val)
    return names[:3]


def _malware_from_data(data, campaign):
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    names = _malware(meta)
    if not names:
        for key in ("name", "campaign"):
            val = _clean_name(data.get(key))
            if val:
                names.append(val)
                break
    title = (campaign.get("title") or "").strip()
    if not names and title and title != campaign.get("slug"):
        names.append(title[:80])
    return names


def _valid_url(value):
    v = (value or "").strip()
    if not (v.startswith("http://") or v.startswith("https://")):
        return False
    low = v.lower()
    if any(x in low for x in ("localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.org")):
        return False
    try:
        host = urlparse(v).hostname or ""
    except ValueError:
        return False
    return bool(host)


def _normalize(ioc_type, value):
    value = (value or "").strip()
    if not value:
        return ioc_type, ""
    if ioc_type in HASH_TYPES:
        value = value.lower()
        if not is_valid_hash(ioc_type, value):
            return ioc_type, ""
    elif ioc_type == "domain":
        value = value.lower().rstrip(".")
        if not is_valid_domain(value):
            return ioc_type, ""
    elif ioc_type == "url":
        if not _valid_url(value):
            return ioc_type, ""
    elif ioc_type == "ip":
        if not is_valid_ip(value):
            return ioc_type, ""
        # 保留 ip:port（校验时会剥端口）
        pass
    return ioc_type, value


def _row(campaign, ioc_type, value, malware):
    ioc_type, value = _normalize(ioc_type, value)
    if not value:
        return None
    return {
        "source": SOURCE,
        "url": campaign.get("report_url") or REPORT_URL.format(campaign["slug"]),
        "title": (campaign.get("title") or campaign["slug"])[:160],
        "ioc_type": ioc_type,
        "ioc_value": value,
        "db_value": value,
        "malware": malware,
        "slug": campaign["slug"],
        "crawl_time": datetime.now().isoformat(),
    }


def _iter_section(section, *list_keys):
    if isinstance(section, list):
        return section
    if not isinstance(section, dict):
        return []
    out = []
    for key in list_keys:
        val = section.get(key)
        if isinstance(val, list):
            out.extend(val)
    return out


def _add_row(rows, seen, campaign, ioc_type, value, malware):
    row = _row(campaign, ioc_type, value, malware)
    if not row:
        return
    key = (row["ioc_type"], row["ioc_value"])
    if key in seen:
        return
    seen.add(key)
    rows.append(row)


def _parse_legacy_network(data, campaign, malware, fallback_conf, rows, seen):
    net = data.get("network_indicators")
    if isinstance(net, dict):
        for blob in (net.get("distribution_infrastructure"), net.get("c2_infrastructure")):
            if not isinstance(blob, dict) or not _keep_item(blob, fallback_conf):
                continue
            _add_row(rows, seen, campaign, "ip", _item_value(blob, "ip", "value"), malware)
            _add_row(rows, seen, campaign, "url", _item_value(blob, "c2_url", "url", "uri"), malware)
            _add_row(rows, seen, campaign, "domain", _item_value(blob, "domain", "fqdn"), malware)

    iocs = data.get("iocs") if isinstance(data.get("iocs"), dict) else None
    if iocs is None and isinstance(data.get("IOCs"), dict):
        iocs = data.get("IOCs")
    if not isinstance(iocs, dict):
        return

    for item in iocs.get("network") or []:
        if not _keep_item(item, fallback_conf):
            continue
        typ = str(item.get("type") or "").lower() if isinstance(item, dict) else ""
        val = _item_value(item, "indicator", "value", "ip", "url", "domain")
        if "url" in typ or val.startswith("http://") or val.startswith("https://"):
            _add_row(rows, seen, campaign, "url", val, malware)
        elif "domain" in typ or "host" in typ:
            _add_row(rows, seen, campaign, "domain", val, malware)
        else:
            _add_row(rows, seen, campaign, "ip", val, malware)

    for item in (iocs.get("Infrastructure") or []) + (iocs.get("IPs") or []):
        if not _keep_item(item, fallback_conf):
            continue
        raw = _item_value(item, "ip", "value") or (item if isinstance(item, str) else "")
        _add_row(rows, seen, campaign, "ip", raw, malware)

    for item in iocs.get("Domains") or []:
        if not _keep_item(item, fallback_conf):
            continue
        raw = _item_value(item, "domain", "value") or (item if isinstance(item, str) else "")
        _add_row(rows, seen, campaign, "domain", raw, malware)


def parse_feed_json(campaign, data):
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    fallback_conf = _conf(meta) or _conf(data)
    if not fallback_conf:
        fallback_conf = str(data.get("confidence_level") or "").strip().lower()
    malware = _malware_from_data(data, campaign)
    rows = []
    seen = set()

    hashes = data.get("file_hashes") if isinstance(data.get("file_hashes"), dict) else {}
    for hash_type in HASH_TYPES:
        for item in hashes.get(hash_type) or []:
            if not _keep_item(item, fallback_conf):
                continue
            _add_row(rows, seen, campaign, hash_type, _item_value(item, "value", "hash", hash_type), malware)

    net = data.get("network_indicators") if isinstance(data.get("network_indicators"), dict) else {}
    for item in _iter_section(net, "ipv4"):
        if not _keep_item(item, fallback_conf):
            continue
        ip = _item_value(item, "ip", "value")
        port = _item_value(item, "port")
        if ip and port and port.isdigit() and ":" not in ip:
            value = "{}:{}".format(ip, port)
        else:
            value = ip
        _add_row(rows, seen, campaign, "ip", value, malware)

    for item in _iter_section(net, "domains", "fqdn", "hostnames"):
        if not _keep_item(item, fallback_conf):
            continue
        _add_row(
            rows, seen, campaign, "domain",
            _item_value(item, "domain", "value", "fqdn", "hostname"),
            malware,
        )

    for item in _iter_section(net, "urls", "url"):
        if not _keep_item(item, fallback_conf):
            continue
        _add_row(rows, seen, campaign, "url", _item_value(item, "url", "value"), malware)

    _parse_legacy_network(data, campaign, malware, fallback_conf, rows, seen)
    return rows


def fetch_campaign_json(slug):
    candidates = [slug]
    stripped = _IP_SUFFIX.sub("", slug)
    if stripped and stripped not in candidates:
        candidates.append(stripped)
    urls = []
    for s in candidates:
        urls.append(IOC_JSON_URL.format(s))
        urls.append("https://the-hunters-ledger.com/ioc-feeds/{}.json".format(s))
    last_404 = False
    for url in urls:
        try:
            r = _get(url)
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                last_404 = True
                continue
            raise
        try:
            return r.json()
        except ValueError:
            return None
    if last_404:
        return None
    return None


def collect_rows(since=None):
    campaigns = discover_campaigns()
    stats = {
        "campaigns": len(campaigns),
        "json_ok": 0,
        "json_miss": 0,
        "skipped_old": 0,
    }
    rows = []
    for camp in campaigns:
        published = camp.get("published")
        if since and published and published < since:
            stats["skipped_old"] += 1
            continue
        data = fetch_campaign_json(camp["slug"])
        if not data:
            stats["json_miss"] += 1
            continue
        stats["json_ok"] += 1
        name = ""
        if isinstance(data.get("metadata"), dict):
            name = (data["metadata"].get("malware_name") or "").strip()
        if not name:
            name = str(data.get("name") or data.get("campaign") or "").strip()
        if name:
            camp["title"] = name
        rows.extend(parse_feed_json(camp, data))
        time.sleep(0.15)
    return rows, stats


def main():
    parser = argparse.ArgumentParser(description="Hunter's Ledger IOC 采集")
    parser.add_argument("--days", type=int, default=0, help="只收近 N 天（0=全部，Atom+列表）")
    parser.add_argument("--no-db", action="store_true")
    parser.add_argument("--db", default="")
    args = parser.parse_args()

    db_path = resolve_db_path(args.db)
    since = None
    if args.days and args.days > 0:
        since = datetime.now(timezone.utc) - timedelta(days=args.days)

    _log("=" * 60)
    _log("  Hunter's Ledger IOC 采集")
    _log("  {}".format(FEED_URL))
    _log("=" * 60)
    _log("  时间窗:", since.strftime("%Y-%m-%d") + " ~ 现在" if since else "全部战役")
    _log("  写入库:", db_path)

    state = load_state(MODULE)
    seen = state.setdefault("seen_fingerprints", {})

    rows, stats = collect_rows(since=since)
    _log("  战役: {}  JSON成功: {}  无JSON: {}  过期丢: {}".format(
        stats["campaigns"], stats["json_ok"], stats["json_miss"], stats["skipped_old"],
    ))
    _log("  本轮 IOC: {}".format(len(rows)))

    new_iocs = []
    new_fps = []
    for row in rows:
        fp = fingerprint(row["ioc_type"], row["ioc_value"])
        if fp in seen:
            continue
        seen[fp] = {"seen_at": datetime.now().isoformat(), "url": row.get("url", "")}
        new_iocs.append(row)
        new_fps.append(fp)

    if new_fps:
        mark_many_seen(MODULE, new_fps)
    else:
        save_state(MODULE, state)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if new_iocs:
        ioc_path = os.path.join(IOC_DIR, "thl_iocs_{}.json".format(ts))
        with open(ioc_path, "w", encoding="utf-8") as f:
            json.dump(new_iocs, f, ensure_ascii=False, indent=2)
        save_delta(MODULE, new_iocs, prefix="iocs")
        _log("  新 IOC:", ioc_path)
        counts = {}
        for r in new_iocs:
            counts[r["ioc_type"]] = counts.get(r["ioc_type"], 0) + 1
        _log("  类型:", ", ".join("{}={}".format(k, v) for k, v in sorted(counts.items())))
        mw = {}
        for r in new_iocs:
            for name in r.get("malware") or []:
                mw[name] = mw.get(name, 0) + 1
        top = sorted(mw.items(), key=lambda x: -x[1])[:8]
        if top:
            _log("  恶意软件 TOP:", ", ".join("{} {}".format(n, c) for n, c in top))
    else:
        _log("  无新增 IOC")
    _log("  本轮拉取: {} 条, 新增: {}".format(len(rows), len(new_iocs)))

    if not args.no_db and new_iocs:
        write_iocs(
            new_iocs,
            db_path,
            source=SOURCE,
            log_url=FEED_URL,
        )
    elif args.no_db:
        _log("  [SKIP] --no-db")
    else:
        _log("  [SKIP] 本轮无新增 IOC")
    return new_iocs


if __name__ == "__main__":
    main()
