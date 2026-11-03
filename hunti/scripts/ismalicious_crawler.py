"""
isMalicious 公开 blocklist 采集（C2 IP / C2 域名 / 勒索域名）

  https://ismalicious.com/blocklist
  https://ismalicious.com/api-docs#blocklists

下载接口是公开路由：不带凭据和 FREE 账号都只给 10% 样本（Lite），BASIC 及以上才是全量。
凭据可选：环境变量 ISMALICIOUS_API_KEY，或 config/ismalicious_api_key.txt，
内容是 base64(apiKey:apiSecret)，不要写进源码。

isMalicious 是聚合源，名单里混有 Cloudflare 等共享 IP 和博彩站，这里先过滤再入库；
入库是 INSERT OR IGNORE，和 ThreatFox 重合的 IP 保留 ThreatFox 原来的来源与家族。

用法:
  py -X utf8 ismalicious_crawler.py
  py -X utf8 ismalicious_crawler.py --no-db
"""
import argparse
import ipaddress
import json
import os
import re
from datetime import datetime

import requests

from crawler_utils import (
    BASE_DIR,
    DEFAULT_NOISE_HOSTS,
    domain_matches_exclusion,
    fingerprint,
    is_valid_ip,
    load_state,
    mark_many_seen,
    save_delta,
    save_state,
)
from export_to_db import resolve_db_path, write_iocs

API = "https://api.ismalicious.com/blocklist/download/"
MODULE = "ismalicious"
IOC_DIR = os.path.join(BASE_DIR, "output", "iocs")
KEY_FILE = os.path.join(BASE_DIR, "config", "ismalicious_api_key.txt")
os.makedirs(IOC_DIR, exist_ok=True)

# (文件名, IOC 类型, 入库来源名)
LISTS = (
    ("blocklist-ips-c2.txt", "ip", "isMalicious C2"),
    ("blocklist-domains-c2.txt", "domain", "isMalicious C2"),
    ("blocklist-domains-ransomware.txt", "domain", "isMalicious Ransomware"),
)

# CDN 共享出口：封了会误伤大量正常站点
SHARED_NETS = [ipaddress.ip_network(n) for n in (
    "104.16.0.0/13", "172.64.0.0/13", "162.158.0.0/15", "188.114.96.0/20", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "198.41.128.0/17", "173.245.48.0/20", "103.21.244.0/22",
    "103.22.200.0/22", "103.31.4.0/22", "131.0.72.0/22", "197.234.240.0/22",
    "151.101.0.0/16",
)]
# 名单里混进来的博彩站，不是 C2
_GAMBLING_RE = re.compile(r"casino|kasino|poker|togel|gacor|judi|slot", re.I)
_GAMBLING_TLDS = {"bet", "casino", "poker"}
# 只有平台根域本身才排除；平台下的具体子域（xxx.workers.dev）是 IOC
_PLATFORM_ROOTS = {
    "workers.dev", "duckdns.org", "ngrok.app", "ngrok.io", "ngrok-free.app", "portmap.host", "portmap.io",
    "github.io", "pages.dev", "vercel.app", "netlify.app", "herokuapp.com", "azurewebsites.net",
    "ydns.eu", "ddns.net", "no-ip.org", "trycloudflare.com",
}
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HuntiIOC/1.0"})


def _log(*args):
    print(*args, flush=True)


def _credential():
    v = (os.environ.get("ISMALICIOUS_API_KEY") or "").strip()
    if v:
        return v
    try:
        with open(KEY_FILE, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _valid_ip(v):
    if not is_valid_ip(v):
        return False
    addr = ipaddress.ip_address(v)
    return not any(addr in n for n in SHARED_NETS)


def _valid_domain(v):
    d = v.lower().rstrip(".")
    labels = d.split(".")
    if len(d) < 4 or len(labels) < 2 or len(labels) > 8:
        return False
    if not all(p and len(p) <= 63 and _LABEL_RE.match(p) for p in labels):
        return False
    if re.match(r"^\d+(\.\d+){3}$", d):
        return False
    if d in _PLATFORM_ROOTS or labels[-1] in _GAMBLING_TLDS or _GAMBLING_RE.search(d):
        return False
    return not domain_matches_exclusion(d, DEFAULT_NOISE_HOSTS)


def fetch_list(name, cred):
    headers = {"X-API-KEY": cred} if cred else {}
    r = session.get(API + name, headers=headers, timeout=120)
    r.raise_for_status()
    meta, values = {}, []
    for line in r.text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith(("#", "!")):
            m = re.match(r"[#!]\s*(Generated|Total entries)\s*:\s*(.+)", s, re.I)
            if m:
                meta[m.group(1).lower()] = m.group(2).strip()
            continue
        values.append(s.split()[0])
    return meta, values


def main():
    parser = argparse.ArgumentParser(description="isMalicious 公开 blocklist 采集")
    parser.add_argument("--db", default="", help="写入的 sqlite 路径")
    parser.add_argument("--no-db", action="store_true", help="只采集，不写数据库")
    args = parser.parse_args()
    db_path = resolve_db_path(args.db)

    _log("=" * 60)
    _log("  isMalicious blocklist（C2 IP / C2 域名 / 勒索域名）")
    _log("  https://ismalicious.com/blocklist")
    _log("=" * 60)
    cred = _credential()
    _log("  凭据: {}".format("已配置" if cred else "未配置（公开样本）"))
    _log("  写入库:", db_path)

    state = load_state(MODULE)
    seen = state.setdefault("seen_fingerprints", {})
    all_rows, new_rows, new_fps = [], [], []
    now = datetime.now().isoformat()
    for name, kind, source in LISTS:
        try:
            meta, values = fetch_list(name, cred)
        except requests.RequestException as e:
            _log("  [FAIL] {} 下载失败: {}".format(name, e))
            continue
        check = _valid_ip if kind == "ip" else _valid_domain
        kept = [v.lower() if kind == "domain" else v for v in values if check(v)]
        kept = list(dict.fromkeys(kept))
        _log("  {:<34s} 名单 {:>6}  过滤后 {:>6}  ({}; 生成 {})".format(
            name, len(values), len(kept), meta.get("total entries", "?"), meta.get("generated", "?")[:19]))
        for v in kept:
            row = {
                "source": source,
                "url": "https://ismalicious.com/blocklist",
                "title": "{} blocklist".format(source),
                "ioc_type": kind,
                "ioc_value": v,
                "threat_actors": [],
                "malware": [],
                "crawl_time": now,
            }
            all_rows.append(row)
            fp = fingerprint(kind, v, source)
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
        path = os.path.join(IOC_DIR, "ismalicious_iocs_{}.json".format(ts))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(new_rows, f, ensure_ascii=False, indent=2)
        save_delta(MODULE, new_rows, prefix="iocs")
        _log("  新 IOC:", path)
    _log("  本轮拉取: {}  新增: {}".format(len(all_rows), len(new_rows)))
    if not args.no_db and all_rows:
        write_iocs(all_rows, db_path, source="", log_url="https://ismalicious.com/blocklist")


if __name__ == "__main__":
    main()
