"""
C2IntelFeeds 采集（Cobalt Strike / Sliver / Havoc 等 C2 IP 与域名）

  https://github.com/drb-ra/C2IntelFeeds
  IPC2s-30day.csv                         近 30 天 C2 IP
  domainC2s-30day-filter-abused.csv       近 30 天 C2 域名（上游已滤掉被滥用的公共域名）

上游是 Shodan 类主动测绘的「Possible」级结果，入库前再过一遍：
  - IP 落在 CDN 边缘 / 公共 DNS（ip_enrich 画像）的剔除
  - 「Fronting Domain」是被借用做域前置的正常域名（如 api.baidubce.com），不收
入库是 INSERT OR IGNORE，已有的 ThreatFox 等来源与家族不会被覆盖。

用法:
  py -X utf8 c2intel_crawler.py
  py -X utf8 c2intel_crawler.py --no-db
"""
import argparse
import json
import os
import re
from datetime import datetime

import requests

from crawler_utils import (
    BASE_DIR,
    fingerprint,
    is_valid_domain,
    is_valid_ip,
    load_state,
    mark_many_seen,
    save_delta,
    save_state,
)
from export_to_db import resolve_db_path, write_iocs

RAW = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/"
REPO = "https://github.com/drb-ra/C2IntelFeeds"
SOURCE = "C2IntelFeeds"
MODULE = "c2intel"
IOC_DIR = os.path.join(BASE_DIR, "output", "iocs")
os.makedirs(IOC_DIR, exist_ok=True)

LISTS = (
    ("IPC2s-30day.csv", "ip"),
    ("domainC2s-30day-filter-abused.csv", "domain"),
)

# 上游标签里的框架名 → 库里统一用的家族名
_FAMILY_ALIASES = {
    "cobaltstrike": "Cobalt Strike",
    "cobalt strike": "Cobalt Strike",
    "metasploit": "Metasploit",
    "sliver": "Sliver",
    "havoc": "Havoc",
    "brute ratel": "Brute Ratel C4",
    "bruteratel": "Brute Ratel C4",
    "mythic": "Mythic",
    "posh": "PoshC2",
    "poshc2": "PoshC2",
    "covenant": "Covenant",
    "deimos": "Deimos",
    "empire": "Empire",
    "villain": "Villain",
    "nimplant": "NimPlant",
}
_LABEL_RE = re.compile(r"^Possible\s+(.+?)\s+C2\b", re.I)

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HuntiIOC/1.0"})


def _log(*args):
    print(*args, flush=True)


def family_from_label(label):
    m = _LABEL_RE.match(label or "")
    if not m:
        return ""
    name = m.group(1).strip()
    return _FAMILY_ALIASES.get(name.lower(), name)


def _shared_infra_checker():
    try:
        from ip_enrich import is_shared_infra
        return is_shared_infra
    except Exception as e:
        _log("  [WARN] 画像索引不可用，CDN 过滤跳过:", e)
        return lambda ip: False


def fetch_list(name):
    r = session.get(RAW + name, timeout=90)
    r.raise_for_status()
    rows = []
    for line in r.text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        value, _, label = s.partition(",")
        rows.append((value.strip(), label.strip()))
    return rows


def main():
    parser = argparse.ArgumentParser(description="C2IntelFeeds C2 IP / 域名采集")
    parser.add_argument("--db", default="", help="写入的 sqlite 路径")
    parser.add_argument("--no-db", action="store_true", help="只采集，不写数据库")
    args = parser.parse_args()
    db_path = resolve_db_path(args.db)

    _log("=" * 60)
    _log("  C2IntelFeeds（近 30 天 C2 IP / 域名）")
    _log("  " + REPO)
    _log("=" * 60)
    _log("  写入库:", db_path)

    shared = _shared_infra_checker()
    state = load_state(MODULE)
    seen = state.setdefault("seen_fingerprints", {})
    all_rows, new_rows, new_fps = [], [], []
    now = datetime.now().isoformat()
    for name, kind in LISTS:
        try:
            items = fetch_list(name)
        except requests.RequestException as e:
            _log("  [FAIL] {} 下载失败: {}".format(name, e))
            continue
        kept, dropped_cdn, dropped_fronting = [], 0, 0
        for value, label in items:
            if kind == "ip":
                if not is_valid_ip(value):
                    continue
                if shared(value):
                    dropped_cdn += 1
                    continue
            else:
                if "fronting domain" in label.lower():
                    dropped_fronting += 1
                    continue
                value = value.lower().rstrip(".")
                if not is_valid_domain(value):
                    continue
            kept.append((value, label))
        kept = list(dict(kept).items())
        _log("  {:<38s} 名单 {:>5}  入选 {:>5}  剔除 CDN {}  剔除前置域名 {}".format(
            name, len(items), len(kept), dropped_cdn, dropped_fronting))
        for value, label in kept:
            fam = family_from_label(label)
            row = {
                "source": SOURCE,
                "url": REPO,
                "title": label or "C2IntelFeeds",
                "ioc_type": kind,
                "ioc_value": value,
                "threat_actors": [],
                "malware": [fam] if fam else [],
                "crawl_time": now,
            }
            all_rows.append(row)
            fp = fingerprint(kind, value, SOURCE)
            if fp not in seen:
                seen[fp] = {"seen_at": now}
                new_rows.append(row)
                new_fps.append(fp)

    if new_fps:
        mark_many_seen(MODULE, new_fps)
    else:
        save_state(MODULE, state)
    if new_rows:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(IOC_DIR, "c2intel_iocs_{}.json".format(ts))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(new_rows, f, ensure_ascii=False, indent=2)
        save_delta(MODULE, new_rows, prefix="iocs")
        _log("  新 IOC:", path)
    _log("  本轮拉取: {}  新增: {}".format(len(all_rows), len(new_rows)))
    if not args.no_db and all_rows:
        write_iocs(all_rows, db_path, source="", log_url=REPO)


if __name__ == "__main__":
    main()
