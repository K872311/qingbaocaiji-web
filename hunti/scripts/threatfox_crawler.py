"""
ThreatFox (abuse.ch) IOC 采集

数据来自官方导出 / Community API，对应浏览页：
  https://threatfox.abuse.ch/browse/

默认拉官方 full 导出（近 6 个月全部未过期 IOC，这是 API/导出能给的全集）。
ThreatFox 自 2025-05-01 起不再导出更早的 IOC。
另拉 recent JSON；有 Auth-Key 时再走 API get_iocs（近 1–7 天）。
--recent-only 只拉最近一批，不拉 full。

Key：环境变量 THREATFOX_AUTH_KEY / ABUSECH_AUTH_KEY
     或 config/threatfox_auth_key.txt（不要写进源码）

用法:
  py -X utf8 threatfox_crawler.py
  py -X utf8 threatfox_crawler.py --days 7
  py -X utf8 threatfox_crawler.py --db-only
  py -X utf8 threatfox_crawler.py --db D:\\other\\ioc_data.db

默认写入 config.ini 的 ioc_db_path（留空则 output/ioc_data.db），可用 --db 覆盖。
"""
import argparse
import csv
import glob
import io
import json
import os
import re
import zipfile
from datetime import datetime

import requests
from crawler_utils import (
    BASE_DIR,
    fingerprint,
    is_valid_hash,
    is_valid_ip,
    load_state,
    load_threatfox_auth_key,
    mark_many_seen,
    save_delta,
    save_state,
)
from export_to_db import db_count, resolve_db_path, write_iocs

OUTPUT_DIR = os.path.join(BASE_DIR, "output")
IOC_DIR = os.path.join(OUTPUT_DIR, "iocs")
os.makedirs(IOC_DIR, exist_ok=True)

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
EXPORT_RECENT = "https://threatfox.abuse.ch/export/json/recent/"
EXPORT_FULL = "https://threatfox.abuse.ch/export/json/full/"
EXPORT_FULL_CSV = "https://threatfox.abuse.ch/export/csv/full/"
# 官方格式：Auth-Key 必须写进路径。/files/exports/full.csv.zip + Auth-Key 头会 401 Missing auth token
EXPORT_API_CSV_V2 = "https://threatfox-api.abuse.ch/v2/files/exports/{}/full.csv.zip"
IOC_PAGE = "https://threatfox.abuse.ch/ioc/{}/"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HuntiIOC/1.0",
    "Accept": "application/json",
}

MODULE = "threatfox"

_TYPE_MAP = {
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
    "ip:port": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "md5": "md5",
    "md5_hash": "md5",
    "sha1": "sha1",
    "sha1_hash": "sha1",
    "sha256": "sha256",
    "sha256_hash": "sha256",
}

session = requests.Session()
session.headers.update(HEADERS)


def _split_csv(value):
    if not value:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return [p.strip() for p in str(value).split(",") if p.strip()]


def _malware_names(item):
    names = []
    printable = (item.get("malware_printable") or "").strip()
    if printable and printable.lower() not in ("unknown", "unknown malware"):
        names.append(printable)
    for alias in _split_csv(item.get("malware_alias")):
        if alias not in names:
            names.append(alias)
    family = (item.get("malware") or "").strip()
    if family and family.lower() not in ("unknown",) and family not in names:
        # win.dridex 这类只在没有可读名时保留
        if not names:
            names.append(family)
    return names


def _normalize_value(ioc_type, value):
    value = (value or "").strip()
    if not value:
        return ioc_type, ""
    if ioc_type == "ip":
        host = value.split("/")[0]
        if host.count(":") == 1 and re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", host):
            value = host.split(":")[0]
        else:
            value = host.split("%")[0]
    elif ioc_type in ("md5", "sha1", "sha256"):
        value = value.lower()
    return ioc_type, value


def _valid_tf_domain(value):
    """ThreatFox 已标注为 domain，只做底线校验，不用博客提取那套 TLD 白名单。"""
    d = (value or "").strip().lower().rstrip(".")
    if len(d) < 4 or "." not in d or " " in d:
        return False
    if "abuse.ch" in d or d.endswith(".threatfox"):
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
    if ioc_type == "ip":
        return is_valid_ip(value)
    if ioc_type == "domain":
        return _valid_tf_domain(value)
    if ioc_type in ("md5", "sha1", "sha256"):
        return is_valid_hash(ioc_type, value)
    if ioc_type == "url":
        low = value.lower()
        if "abuse.ch" in low or "threatfox." in low:
            return False
        return low.startswith("http://") or low.startswith("https://")
    return False


def _row(ioc_id, item):
    ioc_type = _TYPE_MAP.get((item.get("ioc_type") or "").lower())
    raw = item.get("ioc_value") or item.get("ioc") or ""
    ioc_type, value = _normalize_value(ioc_type, raw)
    if not ioc_type or not value or not _valid(ioc_type, value):
        return None
    ref = (item.get("reference") or "").strip()
    url = ref if ref.startswith("http") else IOC_PAGE.format(ioc_id or item.get("id") or "")
    title = (item.get("threat_type_desc") or item.get("threat_type") or "ThreatFox IOC")[:160]
    malware = _malware_names(item)
    raw_s = (raw or "").strip()
    db_value = raw_s if ioc_type == "ip" else value
    return {
        "source": "ThreatFox",
        "url": url,
        "title": title,
        "ioc_type": ioc_type,
        "ioc_value": value,
        "db_value": db_value,
        "threat_actors": [],
        "malware": malware,
        "confidence": item.get("confidence_level", ""),
        "first_seen": item.get("first_seen") or item.get("first_seen_utc") or "",
        "threat_type": item.get("threat_type") or "",
        "reporter": item.get("reporter") or "",
        "crawl_time": datetime.now().isoformat(),
    }


def _iter_export_items(data):
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        for item in data["data"]:
            if isinstance(item, dict):
                yield str(item.get("id") or ""), item
        return
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield str(item.get("id") or ""), item
        return
    if isinstance(data, dict):
        for ioc_id, payload in data.items():
            if ioc_id in ("query_status", "data"):
                continue
            items = payload if isinstance(payload, list) else [payload]
            for item in items:
                if isinstance(item, dict):
                    yield str(ioc_id), item


def _rows_from_json_bytes(raw):
    data = json.loads(raw)
    if isinstance(data, dict) and data.get("status") in (401, 403, "401", "403"):
        raise RuntimeError("导出鉴权失败: {}".format(data.get("message") or data.get("status")))
    rows = []
    for ioc_id, item in _iter_export_items(data):
        row = _row(ioc_id, item)
        if row:
            rows.append(row)
    return rows


def _csv_header_from_comment(line):
    rest = line.lstrip("#").strip()
    if "ioc_value" in rest and ("first_seen" in rest or "ioc_id" in rest):
        return rest
    return ""


def _rows_from_csv_bytes(raw):
    text = raw.decode("utf-8", errors="replace")
    header = None
    data_lines = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            maybe = _csv_header_from_comment(s)
            if maybe:
                header = maybe
            continue
        data_lines.append(ln)
    if not data_lines:
        return []
    if not header:
        header = data_lines[0]
        data_lines = data_lines[1:]
    body = header + "\n" + "\n".join(data_lines)
    reader = csv.DictReader(io.StringIO(body), skipinitialspace=True)
    rows = []
    for rec in reader:
        rec = {(k or "").strip(): (v.strip() if isinstance(v, str) else v) for k, v in rec.items()}
        item = {
            "ioc_value": rec.get("ioc_value") or rec.get("ioc") or "",
            "ioc_type": rec.get("ioc_type") or "",
            "threat_type": rec.get("threat_type") or "",
            "malware": rec.get("fk_malware") or rec.get("malware") or "",
            "malware_alias": rec.get("malware_alias") or "",
            "malware_printable": rec.get("malware_printable") or "",
            "confidence_level": rec.get("confidence_level") or "",
            "first_seen_utc": rec.get("first_seen_utc") or rec.get("first_seen") or "",
            "reference": rec.get("reference") or "",
            "reporter": rec.get("reporter") or "",
            "tags": rec.get("tags") or "",
        }
        row = _row(rec.get("id") or rec.get("ioc_id") or "", item)
        if row:
            rows.append(row)
    return rows


def _parse_export_payload(content, content_type=""):
    ctype = (content_type or "").lower()
    if not content:
        raise RuntimeError("导出为空")
    if content[:1] == b"<" or "html" in ctype:
        raise RuntimeError("导出返回 HTML（可能需要 Auth-Key 或被拦截）")
    if content[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            names = zf.namelist()
            if not names:
                raise RuntimeError("zip 为空")
            inner = zf.read(names[0])
            low = names[0].lower()
            if low.endswith(".csv"):
                return _rows_from_csv_bytes(inner)
            return _rows_from_json_bytes(inner)
    if content.lstrip()[:1] in (b"{", b"["):
        return _rows_from_json_bytes(content)
    if b"," in content[:400] or content.lstrip()[:1] == b"#":
        return _rows_from_csv_bytes(content)
    raise RuntimeError("无法识别导出格式")


def fetch_export(url, timeout=180, auth_key=""):
    headers = {"Accept": "*/*"}
    if auth_key:
        headers["Auth-Key"] = auth_key
    r = session.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return _parse_export_payload(r.content, r.headers.get("Content-Type", ""))


def fetch_full_export(auth_key=""):
    labeled = []
    if auth_key:
        labeled.append(("v2 full.csv.zip", EXPORT_API_CSV_V2.format(auth_key)))
    labeled.extend([
        ("classic json full", EXPORT_FULL),
        ("classic csv full", EXPORT_FULL_CSV),
    ])
    best = []
    last_err = None
    for name, url in labeled:
        try:
            rows = fetch_export(url, timeout=300, auth_key=auth_key)
            print("    {}: {} 条".format(name, len(rows)))
            if len(rows) > len(best):
                best = rows
            if len(best) >= 1000:
                return best
        except Exception as e:
            last_err = e
            print("    {} 失败: {}".format(name, e))
    if not best:
        raise RuntimeError(str(last_err))
    return best


def fetch_api_recent(auth_key, days=7):
    days = max(1, min(int(days or 7), 7))
    headers = {"Auth-Key": auth_key}
    r = session.post(
        API_URL,
        headers=headers,
        json={"query": "get_iocs", "days": days},
        timeout=60,
    )
    r.raise_for_status()
    payload = r.json()
    status = payload.get("query_status")
    if status != "ok":
        raise RuntimeError("API 状态: {}".format(status or "unknown"))
    rows = []
    for item in payload.get("data") or []:
        if not isinstance(item, dict):
            continue
        row = _row(str(item.get("id") or ""), item)
        if row:
            rows.append(row)
    return rows


def load_saved_tf_iocs():
    items = []
    seen = set()
    history_dir = os.path.join(OUTPUT_DIR, "history", MODULE)
    paths = []
    paths.extend(sorted(glob.glob(os.path.join(IOC_DIR, "tf_iocs_*.json"))))
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


def _dedupe_new(rows, seen):
    new_iocs = []
    new_fps = []
    for row in rows:
        fp = fingerprint(row["ioc_type"], row["ioc_value"])
        if fp in seen:
            continue
        seen[fp] = {"seen_at": datetime.now().isoformat(), "url": row.get("url", "")}
        new_iocs.append(row)
        new_fps.append(fp)
    return new_iocs, new_fps


def main():
    parser = argparse.ArgumentParser(description="ThreatFox IOC 采集")
    parser.add_argument("--full", action="store_true", help="拉取近 6 个月全部未过期 IOC（默认就会拉）")
    parser.add_argument("--recent-only", action="store_true", help="只拉 recent / API，不拉 full 全集")
    parser.add_argument("--days", type=int, default=7, help="有 Auth-Key 时 API 回溯天数，1–7")
    parser.add_argument(
        "--db",
        default="",
        help="写入的 sqlite 路径（默认 config.ini 的 ioc_db_path）",
    )
    parser.add_argument("--no-db", action="store_true", help="只采集，不写数据库")
    parser.add_argument("--db-all", action="store_true", help="把已保存的全部 IOC 写入数据库")
    parser.add_argument("--db-only", action="store_true", help="不联网，只把已保存 IOC 写入数据库")
    args = parser.parse_args()

    db_path = resolve_db_path(args.db)
    new_iocs = []

    if args.db_only:
        print("=" * 60)
        print("  ThreatFox 入库（不联网）")
        print("=" * 60)
        to_write = load_saved_tf_iocs()
        if not to_write:
            print("  未找到已保存的 ThreatFox IOC")
            return []
        print("  已保存 IOC: {} 条".format(len(to_write)))
        if not args.no_db:
            write_iocs(to_write, db_path, source="ThreatFox",
                       log_url="https://threatfox.abuse.ch/browse/")
        return to_write

    print("=" * 60)
    print("  ThreatFox 情报采集")
    print("  https://threatfox.abuse.ch/browse/")
    print("=" * 60)

    auth_key = load_threatfox_auth_key()
    print("  Auth-Key:", "已配置" if auth_key else "未配置（用公开 JSON 导出）")
    print("  写入库:", db_path)

    state = load_state(MODULE)
    seen = state.setdefault("seen_fingerprints", {})

    sources = []
    if not args.recent_only:
        try:
            full_rows = fetch_full_export(auth_key)
            sources.append(("full 导出", full_rows))
            print("  full 导出（近6个月全部）: {} 条".format(len(full_rows)))
        except Exception as e:
            print("  full 导出失败: {}".format(e))

    try:
        recent_rows = fetch_export(EXPORT_RECENT, timeout=120, auth_key=auth_key)
        sources.append(("recent 导出", recent_rows))
        print("  recent 导出: {} 条".format(len(recent_rows)))
    except Exception as e:
        print("  recent 导出失败: {}".format(e))

    if auth_key:
        try:
            api_rows = fetch_api_recent(auth_key, args.days)
            sources.append(("API {}天".format(args.days), api_rows))
            print("  API get_iocs ({}天): {} 条".format(args.days, len(api_rows)))
        except Exception as e:
            print("  API 失败: {}".format(e))

    if not sources:
        print("  无可用数据源")
        save_state(MODULE, state)
        return []

    merged = []
    seen_values = set()
    for _name, rows in sources:
        for row in rows:
            key = "{}|{}".format(row["ioc_type"], row["ioc_value"].lower())
            if key in seen_values:
                continue
            seen_values.add(key)
            merged.append(row)

    new_iocs, new_fps = _dedupe_new(merged, seen)
    if new_fps:
        mark_many_seen(MODULE, new_fps)
    else:
        save_state(MODULE, state)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if new_iocs:
        ioc_path = os.path.join(IOC_DIR, "tf_iocs_{}.json".format(ts))
        with open(ioc_path, "w", encoding="utf-8") as f:
            json.dump(new_iocs, f, ensure_ascii=False, indent=2)
        save_delta(MODULE, new_iocs, prefix="iocs")
        print("  新 IOC:", ioc_path)
        counts = {}
        for r in new_iocs:
            counts[r["ioc_type"]] = counts.get(r["ioc_type"], 0) + 1
        print("  类型:", ", ".join("{}={}".format(k, v) for k, v in sorted(counts.items())))
        mw = {}
        for r in new_iocs:
            for name in r.get("malware") or []:
                mw[name] = mw.get(name, 0) + 1
        top = sorted(mw.items(), key=lambda x: -x[1])[:8]
        if top:
            print("  恶意软件 TOP:", ", ".join("{} {}".format(n, c) for n, c in top))
    else:
        print("  无新增 IOC")
    print("  本轮拉取: {} 条, 新增: {}".format(len(merged), len(new_iocs)))
    if not args.no_db:
        need_all = args.db_all or db_count(db_path) == 0
        to_write = load_saved_tf_iocs() if need_all else new_iocs
        if to_write:
            write_iocs(to_write, db_path, source="ThreatFox",
                       log_url="https://threatfox.abuse.ch/browse/")
        else:
            print("  [SKIP] 本轮无新增 IOC")
    return new_iocs


if __name__ == "__main__":
    main()
