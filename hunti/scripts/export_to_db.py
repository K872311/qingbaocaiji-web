"""
按样例库格式写入情报库。

库路径: config/config.ini 的 [IOC Database] ioc_db_path，留空则用 output/ioc_data.db

ioc_records(type, value, ip_only, source, malware)
  type    : ip | domain | url | file_hash
  value   : IP 带端口则原样保留（1.2.3.4:8080）；哈希/域名/URL 小写
  ip_only : 仅 type=ip 时填纯 IP，其余空字符串
  source  : 短来源名（ThreatFox / MalwareBazaar），不拼组织名
  malware : 单个家族名（win.stealc / Trojan），没有则空

crawl_logs(source_url, start_time, end_time, status, iocs_found, error_message)
"""
import configparser
import json
import os
import re
import sqlite3
import glob
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
DEFAULT_DB_PATH = os.path.join(OUTPUT_DIR, "ioc_data.db")

TYPE_MAP = {
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
    "ip:port": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "file_hash": "file_hash",
    "sha256": "file_hash",
    "sha256_hash": "file_hash",
    "md5": "file_hash",
    "md5_hash": "file_hash",
    "sha1": "file_hash",
    "sha1_hash": "file_hash",
}

_IPV4_PORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$")


def get_db_path():
    config_path = os.path.join(BASE_DIR, "config", "config.ini")
    if not os.path.exists(config_path):
        config_path = os.path.join(BASE_DIR, "config", "config.ini.example")
    if not os.path.exists(config_path):
        return ""
    config = configparser.ConfigParser()
    config.read(config_path, encoding="utf-8")
    try:
        return config.get("IOC Database", "ioc_db_path")
    except (configparser.NoSectionError, configparser.NoOptionError):
        return ""


def resolve_db_path(override=""):
    path = (override or "").strip() or get_db_path() or DEFAULT_DB_PATH
    return os.path.abspath(path)


def connect_db(db_path):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.text_factory = str
    return conn


def _first_text(items):
    if isinstance(items, str):
        return items.strip()[:200]
    out = ""
    for item in items or []:
        if isinstance(item, dict):
            item = item.get("value") or item.get("name") or ""
        text = str(item).strip() if item else ""
        if text:
            return text[:200]
    return out


def _as_text_list(items):
    out = []
    for item in items or []:
        if isinstance(item, dict):
            item = item.get("value") or item.get("name") or ""
        text = str(item).strip() if item else ""
        if text and text not in out:
            out.append(text)
    return out


def extract_ip_only(value):
    """与 0707 extractIPOnly 一致：1.2.3.4:8080 → 1.2.3.4，IPv6 不拆。"""
    v = (value or "").strip()
    if not v:
        return ""
    host = v.split("/")[0]
    m = _IPV4_PORT.match(host)
    if m:
        return m.group(1)
    if host.startswith("[") and "]:" in host:
        return host[1:host.index("]")]
    return host.split("%")[0]


def to_sample_rows(iocs, source=""):
    """转成样例库一行：(type, value, ip_only, source, malware)。"""
    default_source = (source or "").strip()
    out = []
    seen = set()
    for row in iocs or []:
        raw_type = (row.get("ioc_type") or row.get("type") or "").lower()
        db_type = TYPE_MAP.get(raw_type)
        value = (row.get("db_value") or row.get("ioc_value") or row.get("value") or "").strip()
        if not db_type or not value:
            continue
        if db_type != "ip":
            value = value.lower()
        ip_only = extract_ip_only(value) if db_type == "ip" else ""
        src = default_source or str(row.get("source") or "").strip()
        if " | " in src:
            src = src.split(" | ", 1)[0].strip()
        src = src[:200] or "hunti"
        malware = _first_text(row.get("malware"))
        if not malware:
            malware = _first_text(row.get("threat_actors"))
        key = (db_type, value.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append((db_type, value, ip_only, src, malware))
        # 与 0707 ThreatFox 相同：ip:port 再补一条纯 IP，方便任意端口匹配
        if db_type == "ip" and ip_only and ip_only != value:
            key2 = (db_type, ip_only.lower())
            if key2 not in seen:
                seen.add(key2)
                out.append((db_type, ip_only, ip_only, src, malware))
    return out


def _ensure_schema(cur):
    cur.execute(
        """CREATE TABLE IF NOT EXISTS ioc_records (
            id INTEGER PRIMARY KEY,
            type TEXT,
            value TEXT,
            ip_only TEXT,
            source TEXT,
            malware TEXT
        )"""
    )
    cur.execute(
        """CREATE TABLE IF NOT EXISTS crawl_logs (
            id INTEGER PRIMARY KEY,
            source_url TEXT,
            start_time TEXT,
            end_time TEXT,
            status TEXT,
            iocs_found INTEGER,
            error_message TEXT
        )"""
    )
    try:
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_type_value ON ioc_records(type, value)"
        )
    except sqlite3.DatabaseError:
        pass


NEW_IOC_LOG_ENV = "HUNTI_NEW_IOC_LOG"


def _log_new_rows(cur, max_rowid):
    """run_all 设置了 HUNTI_NEW_IOC_LOG 时，把本次真正新插入的行追加到该 jsonl。"""
    path = os.environ.get(NEW_IOC_LOG_ENV, "").strip()
    if not path:
        return
    new_rows = cur.execute(
        "SELECT type, value, ip_only, source, malware FROM ioc_records WHERE rowid > ?",
        (max_rowid,),
    ).fetchall()
    with open(path, "a", encoding="utf-8") as f:
        for t, v, ip, src, mal in new_rows:
            f.write(json.dumps(
                {"type": t, "value": v, "ip_only": ip or "", "source": src or "", "malware": mal or ""},
                ensure_ascii=False,
            ) + "\n")


def write_to_db(iocs, db_path, label="", source="", log_url="", quiet=False):
    if not db_path:
        print("  [SKIP] 未指定数据库路径")
        return 0
    rows = to_sample_rows(iocs, source=source)
    if not rows:
        print("  [SKIP] 无 IOC 可写入 {}".format(db_path))
        return 0
    parent = os.path.dirname(os.path.abspath(db_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = connect_db(db_path)
    cur = conn.cursor()
    _ensure_schema(cur)
    before = cur.execute("SELECT COUNT(*) FROM ioc_records").fetchone()[0]
    max_rowid = cur.execute("SELECT MAX(rowid) FROM ioc_records").fetchone()[0] or 0
    t0 = datetime.now().isoformat()
    cur.executemany(
        "INSERT OR IGNORE INTO ioc_records (type, value, ip_only, source, malware) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    after = cur.execute("SELECT COUNT(*) FROM ioc_records").fetchone()[0]
    inserted = max(0, after - before)
    if inserted:
        _log_new_rows(cur, max_rowid)
    skipped = max(0, len(rows) - inserted)
    t1 = datetime.now().isoformat()
    cur.execute(
        """INSERT INTO crawl_logs (source_url, start_time, end_time, status, iocs_found)
           VALUES (?, ?, ?, ?, ?)""",
        (log_url or "hunti_run_all", t0, t1, "success", inserted),
    )
    conn.commit()
    try:
        cur.execute("PRAGMA wal_checkpoint(PASSIVE)")
    except sqlite3.DatabaseError:
        pass
    conn.close()
    if not quiet:
        tag = "[{}] ".format(label) if label else ""
        print("  {}DB: {}".format(tag, db_path))
        print("  待写入: {}  新入库: {}  已存在跳过: {}  库总量: {} → {}".format(
            len(rows), inserted, skipped, before, after,
        ))
    return inserted


def db_count(db_path):
    if not db_path or not os.path.exists(db_path):
        return 0
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        n = conn.execute("SELECT COUNT(*) FROM ioc_records").fetchone()[0]
        conn.close()
        return int(n)
    except sqlite3.DatabaseError:
        return 0


def write_iocs(iocs, db_path="", source="", log_url="", quiet=False):
    if not iocs:
        if not quiet:
            print("  [SKIP] 无 IOC 可写库")
        return 0
    return write_to_db(
        iocs,
        resolve_db_path(db_path),
        source=source,
        log_url=log_url,
        quiet=quiet,
    )


def main():
    db_path = resolve_db_path()
    if not db_path:
        print("  [SKIP] 未配置数据库路径，跳过 DB 写入")
        return False

    pattern = os.path.join(OUTPUT_DIR, "all_iocs_detail_*.json")
    files = sorted(glob.glob(pattern))
    if not files:
        print("[FAIL] 未找到 all_iocs_detail_*.json 在 {}/".format(OUTPUT_DIR))
        return False

    latest = files[-1]
    print("读取: {}".format(latest))
    with open(latest, "r", encoding="utf-8") as f:
        data = json.load(f)

    iocs = data.get("iocs", [])
    print("IOC 总数: {}".format(len(iocs)))
    if not iocs:
        print("  [SKIP] 无 IOC 数据")
        return False

    preview_rows = [
        {"type": t, "value": v, "ip_only": ip, "source": src, "malware": mal}
        for t, v, ip, src, mal in to_sample_rows(iocs)
    ]
    inserted = write_to_db(iocs, db_path, source="", log_url="hunti_run_all")
    preview_path = os.path.join(OUTPUT_DIR, "ioc_db_preview.json")
    with open(preview_path, "w", encoding="utf-8") as f:
        json.dump({"total": len(preview_rows), "rows": preview_rows}, f, ensure_ascii=False, indent=2)
    print("  预览: {} ({} 条)".format(preview_path, len(preview_rows)))
    return inserted >= 0


if __name__ == "__main__":
    ok = main()
    raise SystemExit(0 if ok else 1)
