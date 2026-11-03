"""
AlienVault OTX / LevelBlue Open Threat Exchange 采集

页面：https://otx.alienvault.com/
API Key：https://otx.alienvault.com/settings
         环境变量 OTX_API_KEY，或 config/otx_api_key.txt（不要写进源码）

默认只拉近 6 个月、带家族/APT/MITRE 上下文的高质量 Pulse。
默认 IOC 类型：sha256 / md5 / sha1 / domain / url（不收 IP，与 MISP 一致）。
接口优先 /api/v1/pulses/activity（subscribed 经常 504）。

用法:
  py -X utf8 otx_crawler.py
  py -X utf8 otx_crawler.py --days 180
  py -X utf8 otx_crawler.py --include-ip
  py -X utf8 otx_crawler.py --no-db
"""
import argparse
import glob
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

import requests
from crawler_utils import (
    BASE_DIR,
    fingerprint,
    is_valid_hash,
    load_otx_api_key,
    load_state,
    mark_many_seen,
    save_delta,
    save_state,
)
from export_to_db import resolve_db_path, write_iocs

OUTPUT_DIR = os.path.join(BASE_DIR, "output")
IOC_DIR = os.path.join(OUTPUT_DIR, "iocs")
os.makedirs(IOC_DIR, exist_ok=True)

API_ROOT = "https://otx.alienvault.com/api/v1"
PULSE_PAGE = "https://otx.alienvault.com/pulse/{}"
SOURCE = "OTX"
MODULE = "otx"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HuntiIOC/1.0",
    "Accept": "application/json",
}

_TYPE_MAP = {
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "filehash-md5": "md5",
    "filehash-sha1": "sha1",
    "filehash-sha256": "sha256",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "ipv4": "ip",
    "ipv6": "ip",
}

TRUSTED_AUTHORS = {
    "alienvault",
    "levelblue",
    "levelblue labs",
}

SKIP_PULSE_KEYS = (
    "tor ", "torlist", "tor exit", "tor node",
    "bitcoin",
    "ipsum",
    "dataplane",
    "blocklist.de",
    "dshield",
    "bruteforce",
    "brute force",
    "ciarmy",
    "cinsscore",
    "greensnow",
    "sslbl",
    "open proxy",
    "openprox",
    "mass scan",
    "scanner ip",
    "honeypot",
    "spamhaus",
    "compromised ips",
)

session = requests.Session()
session.headers.update(HEADERS)


def _log(*args):
    print(*args, flush=True)


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


def _as_list(value):
    if not value:
        return []
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, dict):
                item = item.get("name") or item.get("display_name") or item.get("id") or ""
            text = str(item).strip()
            if text and text not in out:
                out.append(text)
        return out
    text = str(value).strip()
    return [text] if text else []


def _pulse_blob(pulse):
    parts = [
        pulse.get("name") or "",
        pulse.get("description") or "",
        " ".join(_as_list(pulse.get("tags"))),
        " ".join(_as_list(pulse.get("malware_families"))),
    ]
    return " ".join(parts).lower()


def _is_noisy_pulse(pulse):
    blob = _pulse_blob(pulse)
    return any(k in blob for k in SKIP_PULSE_KEYS)


def _is_trusted_author(pulse):
    author = (pulse.get("author_name") or "").strip().lower()
    return author in TRUSTED_AUTHORS


def _has_context(pulse):
    if _as_list(pulse.get("malware_families")):
        return True
    if (pulse.get("adversary") or "").strip():
        return True
    if _as_list(pulse.get("attack_ids")):
        return True
    return False


def _keep_pulse(pulse):
    if _is_noisy_pulse(pulse):
        return False
    if _is_trusted_author(pulse):
        return True
    return _has_context(pulse)


def _valid_domain(value):
    d = (value or "").strip().lower().rstrip(".")
    if len(d) < 4 or "." not in d or " " in d:
        return False
    if "alienvault.com" in d or "otx.alienvault" in d:
        return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d):
        return False
    labels = d.split(".")
    if len(labels) < 2 or len(labels) > 8:
        return False
    for p in labels:
        if not p or len(p) > 63:
            return False
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", p):
            return False
    return True


def _valid(ioc_type, value):
    if ioc_type == "domain":
        return _valid_domain(value)
    if ioc_type in ("md5", "sha1", "sha256"):
        return is_valid_hash(ioc_type, value)
    if ioc_type == "url":
        low = (value or "").lower()
        if "alienvault.com" in low or "otx.alienvault" in low:
            return False
        return low.startswith("http://") or low.startswith("https://")
    if ioc_type == "ip":
        from crawler_utils import is_valid_ip
        return is_valid_ip(value)
    return False


def _normalize_value(ioc_type, value):
    value = (value or "").strip()
    if not value:
        return ioc_type, ""
    if ioc_type in ("md5", "sha1", "sha256"):
        value = value.lower()
    elif ioc_type == "domain":
        value = value.lower().rstrip(".")
    return ioc_type, value


def _malware_names(pulse):
    names = []
    for item in _as_list(pulse.get("malware_families")):
        if item.lower() in ("unknown", "unknown malware", "malware"):
            continue
        if item not in names:
            names.append(item)
    adv = (pulse.get("adversary") or "").strip()
    if adv and adv not in names:
        names.append(adv)
    return names


def _row(pulse, indicator):
    ioc_type = _TYPE_MAP.get((indicator.get("type") or "").lower())
    raw = indicator.get("indicator") or indicator.get("indicator_value") or ""
    ioc_type, value = _normalize_value(ioc_type, raw)
    if not ioc_type or not value or not _valid(ioc_type, value):
        return None
    pulse_id = pulse.get("id") or ""
    malware = _malware_names(pulse)
    actors = []
    adv = (pulse.get("adversary") or "").strip()
    if adv:
        actors.append(adv)
    title = (pulse.get("name") or "OTX Pulse")[:160]
    return {
        "source": SOURCE,
        "url": PULSE_PAGE.format(pulse_id),
        "title": title,
        "ioc_type": ioc_type,
        "ioc_value": value,
        "db_value": value,
        "threat_actors": actors,
        "malware": malware,
        "author": pulse.get("author_name") or "",
        "pulse_id": str(pulse_id),
        "crawl_time": datetime.now().isoformat(),
    }


def _get(path, api_key, params=None, timeout=90, retries=4):
    headers = dict(HEADERS)
    headers["X-OTX-API-KEY"] = api_key
    url = path if path.startswith("http") else API_ROOT + path
    last = None
    for attempt in range(1, retries + 1):
        try:
            r = session.get(url, headers=headers, params=params, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last = e
            wait = min(20, 2 * attempt)
            _log("    [retry {}/{}] {}  {}s".format(attempt, retries, e.__class__.__name__, wait))
            time.sleep(wait)
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code in (429, 502, 503, 504):
                last = e
                wait = min(30, 3 * attempt)
                _log("    [retry {}/{}] HTTP {}  {}s".format(
                    attempt, retries, e.response.status_code, wait,
                ))
                time.sleep(wait)
                continue
            raise
    raise last


def fetch_user(api_key):
    return _get("/users/me", api_key)


def iter_activity_pulses(api_key, modified_since, limit=20, max_pages=80):
    since = modified_since.strftime("%Y-%m-%dT%H:%M:%S")
    empty_pages = 0
    for page in range(1, max_pages + 1):
        data = _get(
            "/pulses/activity",
            api_key,
            params={"limit": limit, "page": page, "modified_since": since},
            timeout=90,
        )
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or not results:
            empty_pages += 1
            if empty_pages >= 2:
                break
            continue
        empty_pages = 0
        for pulse in results:
            if isinstance(pulse, dict):
                yield pulse
        if not data.get("next"):
            break
        time.sleep(0.2)


def fetch_pulse_detail(api_key, pulse_id):
    if not pulse_id:
        return {}
    try:
        return _get("/pulses/{}".format(pulse_id), api_key, timeout=45)
    except Exception:
        return {}


def fetch_pulse_indicators(api_key, pulse_id, limit=1000):
    out = []
    path = "/pulses/{}/indicators".format(pulse_id)
    params = {"limit": min(limit, 1000)}
    pages = 0
    while path and pages < 20:
        try:
            data = _get(path, api_key, params=params if pages == 0 else None, timeout=45)
        except Exception:
            break
        pages += 1
        results = data.get("results") if isinstance(data, dict) else None
        if isinstance(results, list):
            out.extend(x for x in results if isinstance(x, dict))
        elif isinstance(data, list):
            out.extend(x for x in data if isinstance(x, dict))
            break
        nxt = ""
        if isinstance(data, dict):
            nxt = (data.get("next") or "").strip()
        path = nxt
        params = None
        if nxt:
            time.sleep(0.12)
    return out


def _indicators_of(pulse, api_key):
    inds = pulse.get("indicators")
    if isinstance(inds, list) and inds:
        extra = pulse.get("indicator_count") or pulse.get("indicators_count") or 0
        try:
            extra = int(extra)
        except (TypeError, ValueError):
            extra = 0
        if extra and extra > len(inds):
            more = fetch_pulse_indicators(api_key, pulse.get("id"))
            if more:
                return more
        return inds
    more = fetch_pulse_indicators(api_key, pulse.get("id"))
    if more:
        return more
    detail = fetch_pulse_detail(api_key, pulse.get("id"))
    if isinstance(detail.get("indicators"), list):
        return detail["indicators"]
    return []


def collect_rows(api_key, since, include_ip=False):
    wanted_types = {"md5", "sha1", "sha256", "domain", "url"}
    if include_ip:
        wanted_types.add("ip")
        _TYPE_MAP.setdefault("ipv4", "ip")

    scanned = kept_pulses = skipped_noise = skipped_ctx = 0
    rows = []
    seen = set()
    try:
        pulse_iter = iter_activity_pulses(api_key, since)
        for pulse in pulse_iter:
            scanned += 1
            modified = _parse_dt(pulse.get("modified") or pulse.get("created"))
            if modified and modified < since:
                continue
            if not _keep_pulse(pulse):
                if _is_noisy_pulse(pulse):
                    skipped_noise += 1
                else:
                    skipped_ctx += 1
                continue
            kept_pulses += 1
            for ind in _indicators_of(pulse, api_key):
                created = _parse_dt(ind.get("created") or ind.get("created_at"))
                if created and created < since:
                    continue
                row = _row(pulse, ind)
                if not row or row["ioc_type"] not in wanted_types:
                    continue
                key = "{}|{}".format(row["ioc_type"], row["ioc_value"].lower())
                if key in seen:
                    continue
                seen.add(key)
                rows.append(row)
            if scanned % 50 == 0:
                _log("    已扫描 Pulse {}，高质量 {}，IOC {}".format(
                    scanned, kept_pulses, len(rows),
                ))
    except Exception as e:
        _log("  [WARN] 拉取中断，保留已解析 IOC: {}".format(e))
    return rows, {
        "scanned": scanned,
        "kept_pulses": kept_pulses,
        "skipped_noise": skipped_noise,
        "skipped_ctx": skipped_ctx,
    }


def load_saved_otx_iocs():
    items = []
    seen = set()
    for path in sorted(glob.glob(os.path.join(IOC_DIR, "otx_iocs_*.json"))):
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
    parser = argparse.ArgumentParser(description="OTX 高质量 IOC 采集")
    parser.add_argument("--days", type=int, default=180, help="回溯天数，默认 180（近半年）")
    parser.add_argument("--include-ip", action="store_true", help="同时收 IPv4（默认不收）")
    parser.add_argument("--db", default="", help="写入的 sqlite 路径")
    parser.add_argument("--no-db", action="store_true", help="只采集，不写数据库")
    args = parser.parse_args()

    db_path = resolve_db_path(args.db)
    api_key = load_otx_api_key()
    since = datetime.now(timezone.utc) - timedelta(days=max(1, args.days))

    _log("=" * 60)
    _log("  OTX / LevelBlue 高质量情报采集")
    _log("  https://otx.alienvault.com/")
    _log("=" * 60)
    _log("  API Key:", "已配置" if api_key else "未配置")
    _log("  时间窗:", since.strftime("%Y-%m-%d"), "~ 现在")
    _log("  写入库:", db_path)
    _log("  收 IP:", "是" if args.include_ip else "否")

    if not api_key:
        _log("  [FAIL] 未找到 OTX API Key（config/otx_api_key.txt 或环境变量 OTX_API_KEY）")
        return []

    try:
        me = fetch_user(api_key)
        _log("  账号:", me.get("username") or me.get("user_id") or "ok")
    except Exception as e:
        _log("  [FAIL] 登录校验失败:", e)
        return []

    state = load_state(MODULE)
    seen = state.setdefault("seen_fingerprints", {})

    rows, stats = collect_rows(api_key, since, include_ip=args.include_ip)
    _log("  Pulse 扫描: {}  高质量: {}  噪音丢: {}  无上下文丢: {}".format(
        stats["scanned"], stats["kept_pulses"], stats["skipped_noise"], stats["skipped_ctx"],
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
        ioc_path = os.path.join(IOC_DIR, "otx_iocs_{}.json".format(ts))
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
            log_url="https://otx.alienvault.com/",
        )
    elif args.no_db:
        _log("  [SKIP] --no-db")
    else:
        _log("  [SKIP] 本轮无新增 IOC")
    return new_iocs


if __name__ == "__main__":
    main()
