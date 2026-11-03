"""
TweetFeed 采集（研究员在 X/Twitter 上公开分享的 IOC）

  https://github.com/0xDanielLopez/TweetFeed
  week.csv / month.csv: date,user,type,value,tags,tweet

首次（无状态）拉 month.csv 补近 30 天，之后每轮拉 week.csv。
类型: ip / domain / url / sha256 / md5。
标签里能认出家族名的（#AsyncRAT、#CobaltStrike…）写进 malware；
只有 #phishing / #malware 这类泛标签的不写家族，避免污染家族统计。
过滤: 公网 IP 且不在 CDN / 公共 DNS；域名与 URL 主机走统一噪声表。

用法:
  py -X utf8 tweetfeed_crawler.py
  py -X utf8 tweetfeed_crawler.py --month     # 强制拉 month.csv
  py -X utf8 tweetfeed_crawler.py --no-db
"""
import argparse
import csv
import io
import json
import os
from datetime import datetime
from urllib.parse import urlsplit

import requests

from crawler_utils import (
    BASE_DIR,
    clean_extracted_url,
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

RAW = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/"
REPO = "https://github.com/0xDanielLopez/TweetFeed"
SOURCE = "TweetFeed"
MODULE = "tweetfeed"
IOC_DIR = os.path.join(BASE_DIR, "output", "iocs")
os.makedirs(IOC_DIR, exist_ok=True)

_TYPE_MAP = {"ip": "ip", "domain": "domain", "url": "url", "sha256": "sha256", "md5": "md5"}

# 不是家族名的泛标签
_GENERIC_TAGS = {
    "phishing", "malware", "scam", "ioc", "iocs", "opendir", "c2", "spam", "suspicious",
    "threatintel", "threatintelligence", "cybersecurity", "infosec", "maldoc", "apt",
    "botnet", "rat", "stealer", "infostealer", "loader", "ransomware", "trojan", "backdoor",
    "fakeupdate", "fakeupdates", "clearfake", "clickfix", "smishing", "crypto", "cryptoscam",
    "drainer", "pishing", "phish", "credential", "credentials", "dfir", "soc", "malspam",
    "kit", "phishingkit", "tds", "dga", "honeypot", "scanner",
    "bruteforce", "webshell", "exploit", "cve", "vulnerability", "bitcoin", "usdt",
}
_FAMILY_ALIASES = {
    "cobaltstrike": "Cobalt Strike", "asyncrat": "AsyncRAT", "remcos": "Remcos",
    "remcosrat": "Remcos", "njrat": "njRAT", "quasarrat": "QuasarRAT", "quasar": "QuasarRAT",
    "agenttesla": "AgentTesla", "formbook": "FormBook", "xloader": "XLoader",
    "lummastealer": "Lumma Stealer", "lumma": "Lumma Stealer", "lummac2": "Lumma Stealer",
    "vidar": "Vidar", "redline": "RedLine Stealer", "redlinestealer": "RedLine Stealer",
    "stealc": "StealC", "amadey": "Amadey", "emotet": "Emotet", "qakbot": "QakBot",
    "icedid": "IcedID", "pikabot": "Pikabot", "darkgate": "DarkGate", "sliver": "Sliver",
    "havoc": "Havoc", "metasploit": "Metasploit", "mirai": "Mirai", "xworm": "XWorm",
    "dcrat": "DCRat", "venomrat": "VenomRAT", "netsupport": "NetSupport RAT",
    "netsupportrat": "NetSupport RAT", "rhadamanthys": "Rhadamanthys", "latrodectus": "Latrodectus",
    "bumblebee": "Bumblebee", "smokeloader": "SmokeLoader", "raccoon": "Raccoon Stealer",
    "acrstealer": "ACR Stealer", "valleyrat": "ValleyRAT", "gh0strat": "Gh0st RAT",
    "socgholish": "SocGholish", "gootloader": "GootLoader",
}

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HuntiIOC/1.0"})


def _log(*args):
    print(*args, flush=True)


def _shared_infra_checker():
    try:
        from ip_enrich import is_shared_infra
        return is_shared_infra
    except Exception as e:
        _log("  [WARN] 画像索引不可用，CDN 过滤跳过:", e)
        return lambda ip: False


def family_from_tags(tags):
    for raw in (tags or "").replace(",", " ").split():
        t = raw.lstrip("#").strip().lower()
        if not t or t in _GENERIC_TAGS:
            continue
        if t in _FAMILY_ALIASES:
            return _FAMILY_ALIASES[t]
    return ""


def normalize(kind, value, shared):
    v = (value or "").strip()
    if kind == "ip":
        ip = v.split(":")[0]
        return ip if is_valid_ip(ip) and not shared(ip) else ""
    if kind == "domain":
        d = v.lower().rstrip(".")
        return d if is_valid_domain(d) else ""
    if kind == "url":
        u = clean_extracted_url(v)
        if not u:
            return ""
        host = (urlsplit(u).hostname or "").lower()
        if is_valid_ip(host) and shared(host):
            return ""
        return u
    if kind in ("sha256", "md5"):
        h = v.lower()
        return h if is_valid_hash(kind, h) else ""
    return ""


def fetch(name):
    r = session.get(RAW + name, timeout=120)
    r.raise_for_status()
    return list(csv.reader(io.StringIO(r.text)))


def main():
    parser = argparse.ArgumentParser(description="TweetFeed IOC 采集")
    parser.add_argument("--db", default="", help="写入的 sqlite 路径")
    parser.add_argument("--no-db", action="store_true", help="只采集，不写数据库")
    parser.add_argument("--month", action="store_true", help="拉 month.csv（默认首轮才拉）")
    args = parser.parse_args()
    db_path = resolve_db_path(args.db)

    state = load_state(MODULE)
    seen = state.setdefault("seen_fingerprints", {})
    feed = "month.csv" if (args.month or not seen) else "week.csv"

    _log("=" * 60)
    _log("  TweetFeed（X/Twitter 研究员分享 IOC）")
    _log("  {}  拉取 {}".format(REPO, feed))
    _log("=" * 60)
    _log("  写入库:", db_path)

    try:
        rows = fetch(feed)
    except requests.RequestException as e:
        _log("  [FAIL] 下载失败:", e)
        return
    shared = _shared_infra_checker()
    now = datetime.now().isoformat()
    all_rows, new_rows, new_fps = [], [], []
    by_type, dropped = {}, 0
    dedup = set()
    for cols in rows:
        if len(cols) < 4:
            continue
        date, user, kind, value = cols[0], cols[1], cols[2].strip().lower(), cols[3]
        tags = cols[4] if len(cols) > 4 else ""
        tweet = cols[5] if len(cols) > 5 else ""
        kind = _TYPE_MAP.get(kind)
        if not kind:
            continue
        v = normalize(kind, value, shared)
        if not v:
            dropped += 1
            continue
        if (kind, v) in dedup:
            continue
        dedup.add((kind, v))
        fam = family_from_tags(tags)
        row = {
            "source": SOURCE,
            "url": tweet if tweet.startswith("https://") else REPO,
            "title": "@{} {}".format(user, tags).strip(),
            "ioc_type": kind,
            "ioc_value": v,
            "threat_actors": [],
            "malware": [fam] if fam else [],
            "published": date,
            "crawl_time": now,
        }
        all_rows.append(row)
        by_type[kind] = by_type.get(kind, 0) + 1
        fp = fingerprint(kind, v, SOURCE)
        if fp not in seen:
            seen[fp] = {"seen_at": now}
            new_rows.append(row)
            new_fps.append(fp)

    _log("  行数 {}  有效 {}  过滤 {}  按类型: {}".format(
        len(rows), len(all_rows), dropped, ", ".join(f"{k}={v}" for k, v in sorted(by_type.items()))))
    if new_fps:
        mark_many_seen(MODULE, new_fps)
    else:
        save_state(MODULE, state)
    if new_rows:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(IOC_DIR, "tweetfeed_iocs_{}.json".format(ts))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(new_rows, f, ensure_ascii=False, indent=2)
        save_delta(MODULE, new_rows, prefix="iocs")
        _log("  新 IOC:", path)
    _log("  本轮拉取: {}  新增: {}".format(len(all_rows), len(new_rows)))
    if not args.no_db and all_rows:
        write_iocs(all_rows, db_path, source="", log_url=REPO)


if __name__ == "__main__":
    main()
