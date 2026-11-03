"""
恶意家族 / 组织索引（加速关键词检索、关联样本、APT 与家族专题页）

主库 ioc_records 的 malware 列没有合适的索引，按家族名 LIKE 扫 580 万行动辄超时。
这里把 malware 拆成单个名字，建一张独立的小库 output/family_index.db：
  families   每个家族的 IOC 总数、按类型计数、主要来源
  fam_rows   每个家族、每种类型最近的若干条主库 rowid（面板按 rowid 回主库取行）
增量：记录上次扫到的最大 rowid，下次只扫新行（主库只追加，rowid 单调递增）。

用法:
  python -X utf8 family_index.py            # 增量（run_all 末尾自动跑）
  python -X utf8 family_index.py --full     # 全量重建
  python -X utf8 family_index.py --stats
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import time
from collections import Counter, defaultdict, deque
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_PATH = os.path.join(BASE_DIR, "output", "family_index.db")
KEEP_PER_TYPE = 200
MAX_TAG_LEN = 40
TYPES = ("ip", "domain", "url", "file_hash")

_SPLIT_RE = re.compile(r"\s*[;|]\s*|,\s+")
_ALIAS_SEP = re.compile(r"[\s\-_.]+")


def split_names(s):
    """与面板 app.split_names 相同的拆分规则。"""
    out = []
    for part in _SPLIT_RE.split(str(s or "")):
        part = part.strip().strip("[]'\"")
        if 2 <= len(part) <= MAX_TAG_LEN and part not in out:
            out.append(part)
    return out


def alias_key(name):
    return _ALIAS_SEP.sub("", (name or "").lower())


def short_source(s):
    s = (s or "").strip()
    s = re.split(r"\s*[|;]\s*|,\s+", s)[0].strip()
    m = re.match(r"^https?://([^/]+)", s, re.I)
    if m:
        s = m.group(1).lower()
    return s[4:] if s.startswith("www.") else s[:60]


def _schema(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS families (
            key TEXT PRIMARY KEY, akey TEXT, name TEXT, total INTEGER,
            n_ip INTEGER, n_domain INTEGER, n_url INTEGER, n_file_hash INTEGER, n_other INTEGER,
            sources TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_fam_akey ON families(akey);
        CREATE INDEX IF NOT EXISTS idx_fam_total ON families(total DESC);
        CREATE TABLE IF NOT EXISTS fam_rows (key TEXT, type TEXT, rid INTEGER);
        CREATE INDEX IF NOT EXISTS idx_famrows ON fam_rows(key, type, rid);
    """)


def _meta(conn, k, default=""):
    row = conn.execute("SELECT v FROM meta WHERE k = ?", (k,)).fetchone()
    return row[0] if row else default


def _set_meta(conn, **kv):
    conn.executemany("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", [(k, str(v)) for k, v in kv.items()])


def build(full=False, src_path="", quiet=False):
    from export_to_db import resolve_db_path
    src = resolve_db_path(src_path)
    if not os.path.isfile(src):
        print("  [SKIP] 找不到主库:", src)
        return 0
    os.makedirs(os.path.dirname(INDEX_PATH), exist_ok=True)
    target = INDEX_PATH + ".build" if full or not os.path.isfile(INDEX_PATH) else INDEX_PATH
    if target.endswith(".build") and os.path.exists(target):
        os.remove(target)
    idx = sqlite3.connect(target)
    _schema(idx)
    last = 0 if target.endswith(".build") else int(_meta(idx, "last_rowid", "0") or 0)
    if _meta(idx, "src_path") and not _same_path(_meta(idx, "src_path"), src):
        last = 0
        idx.close()
        os.remove(target)
        target = INDEX_PATH + ".build"
        idx = sqlite3.connect(target)
        _schema(idx)

    main = sqlite3.connect("file:{}?mode=ro".format(src.replace("\\", "/")), uri=True, timeout=30)
    main.text_factory = lambda b: b.decode("utf-8", "replace")
    max_rid = main.execute("SELECT MAX(rowid) FROM ioc_records").fetchone()[0] or 0
    t0 = time.time()
    if not quiet:
        print("  主库: {}  扫描 rowid {} → {}{}".format(src, last, max_rid, "（全量）" if last == 0 else "（增量）"))

    agg = {}
    rids = defaultdict(lambda: deque(maxlen=KEEP_PER_TYPE))
    scanned = 0
    cur = main.execute(
        "SELECT rowid, type, source, malware FROM ioc_records "
        "WHERE rowid > ? AND rowid <= ? AND malware IS NOT NULL AND malware != ''",
        (last, max_rid))
    while True:
        batch = cur.fetchmany(50000)
        if not batch:
            break
        for rid, typ, source, malware in batch:
            scanned += 1
            if typ == "ip_profile":
                continue
            t = typ if typ in TYPES else "other"
            src_name = short_source(source)
            for name in split_names(malware):
                key = name.lower()
                a = agg.get(key)
                if a is None:
                    a = agg[key] = {"name": name, "total": 0, "ip": 0, "domain": 0, "url": 0,
                                    "file_hash": 0, "other": 0, "sources": Counter()}
                a["total"] += 1
                a[t] += 1
                if src_name:
                    a["sources"][src_name] += 1
                if t != "other":
                    rids[(key, t)].append(rid)
        if not quiet and scanned and scanned % 500000 < 50000:
            print("    已扫描 {:,} 行，家族 {:,} 个，{:.0f}s".format(scanned, len(agg), time.time() - t0), flush=True)
    main.close()

    # 合并进索引库
    touched = list(agg.keys())
    for key in touched:
        a = agg[key]
        old = idx.execute(
            "SELECT name, total, n_ip, n_domain, n_url, n_file_hash, n_other, sources FROM families WHERE key = ?",
            (key,)).fetchone()
        srcs = a["sources"]
        if old:
            srcs = Counter(json.loads(old[7] or "{}")) + srcs
            vals = (old[0], old[1] + a["total"], old[2] + a["ip"], old[3] + a["domain"], old[4] + a["url"],
                    old[5] + a["file_hash"], old[6] + a["other"])
        else:
            vals = (a["name"], a["total"], a["ip"], a["domain"], a["url"], a["file_hash"], a["other"])
        idx.execute(
            "INSERT OR REPLACE INTO families (key, akey, name, total, n_ip, n_domain, n_url, n_file_hash, n_other, sources) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (key, alias_key(key)) + vals + (json.dumps(dict(srcs.most_common(8)), ensure_ascii=False),))
    idx.executemany("INSERT INTO fam_rows (key, type, rid) VALUES (?, ?, ?)",
                    [(k, t, r) for (k, t), dq in rids.items() for r in dq])
    if last:
        for (k, t) in rids.keys():
            idx.execute(
                "DELETE FROM fam_rows WHERE rowid IN (SELECT rowid FROM fam_rows WHERE key = ? AND type = ? "
                "ORDER BY rid DESC LIMIT -1 OFFSET ?)", (k, t, KEEP_PER_TYPE))
    n_fam = idx.execute("SELECT COUNT(*) FROM families").fetchone()[0]
    _set_meta(idx, last_rowid=max_rid, built_at=datetime.now().isoformat(timespec="seconds"),
              src_path=src, families=n_fam)
    idx.commit()
    idx.close()
    if target.endswith(".build"):
        os.replace(target, INDEX_PATH)
    if not quiet:
        print("  扫描 {:,} 行，本轮涉及家族 {:,} 个，索引共 {:,} 个家族，用时 {:.1f}s".format(
            scanned, len(touched), n_fam, time.time() - t0))
    return len(touched)


# ── 面板读取接口 ────────────────────────────────────────────────────

EXPECTED_SRC = ""   # 面板启动时设为它读的主库；索引来自别的库时 rowid 对不上，视为不可用


def _same_path(a, b):
    return os.path.normcase(os.path.abspath(a or "")) == os.path.normcase(os.path.abspath(b or ""))


def open_ro():
    if not os.path.isfile(INDEX_PATH):
        return None
    try:
        conn = sqlite3.connect("file:{}?mode=ro".format(INDEX_PATH.replace("\\", "/")), uri=True,
                               timeout=5, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        if EXPECTED_SRC and not _same_path(_meta(conn, "src_path"), EXPECTED_SRC):
            conn.close()
            return None
        return conn
    except sqlite3.Error:
        return None


def _fam_dict(r):
    return {
        "key": r["key"], "akey": r["akey"], "name": r["name"], "total": r["total"],
        "counts": {"ip": r["n_ip"], "domain": r["n_domain"], "url": r["n_url"], "file_hash": r["n_file_hash"]},
        "sources": json.loads(r["sources"] or "{}"),
    }


def find_families(keyword, limit=30):
    """关键词 → 家族：先精确（大小写 / 分隔符无关），再子串；按 IOC 数排序。"""
    conn = open_ro()
    if conn is None:
        return None
    try:
        kw = (keyword or "").strip().lower()
        ak = alias_key(kw)
        if len(ak) < 2:
            return []
        exact = conn.execute("SELECT * FROM families WHERE key = ? OR akey = ? ORDER BY total DESC",
                             (kw, ak)).fetchall()
        seen = {r["key"] for r in exact}
        esc = ak.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        more = conn.execute(
            "SELECT * FROM families WHERE akey LIKE ? ESCAPE '\\' ORDER BY total DESC LIMIT ?",
            ("%" + esc + "%", limit)).fetchall() if len(ak) >= 3 else []
        out = [_fam_dict(r) for r in exact] + [_fam_dict(r) for r in more if r["key"] not in seen]
        return out[:limit]
    finally:
        conn.close()


def families_by_akeys(akeys):
    conn = open_ro()
    if conn is None or not akeys:
        return []
    try:
        akeys = list(akeys)[:300]
        rows = conn.execute("SELECT * FROM families WHERE akey IN ({}) ORDER BY total DESC".format(
            ",".join("?" * len(akeys))), akeys).fetchall()
        return [_fam_dict(r) for r in rows]
    finally:
        conn.close()


def rowids_for(keys, types=None, limit=300):
    conn = open_ro()
    if conn is None or not keys:
        return []
    try:
        keys = list(keys)[:100]
        sql = "SELECT rid FROM fam_rows WHERE key IN ({})".format(",".join("?" * len(keys)))
        params = list(keys)
        if types:
            sql += " AND type IN ({})".format(",".join("?" * len(types)))
            params += list(types)
        sql += " ORDER BY rid DESC LIMIT ?"
        params.append(limit)
        return list(dict.fromkeys(r[0] for r in conn.execute(sql, params)))
    finally:
        conn.close()


def top_families(q="", limit=50, offset=0):
    conn = open_ro()
    if conn is None:
        return None, 0
    try:
        if q:
            esc = alias_key(q).replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
            where, params = "WHERE akey LIKE ? ESCAPE '\\'", ["%" + esc + "%"]
        else:
            where, params = "", []
        total = conn.execute("SELECT COUNT(*) FROM families " + where, params).fetchone()[0]
        rows = conn.execute("SELECT * FROM families {} ORDER BY total DESC LIMIT ? OFFSET ?".format(where),
                            params + [limit, offset]).fetchall()
        return [_fam_dict(r) for r in rows], total
    finally:
        conn.close()


def akey_totals():
    """akey → 该名字的 IOC 总数（APT 列表批量统计用）。"""
    conn = open_ro()
    if conn is None:
        return {}
    try:
        out = {}
        for ak, total in conn.execute("SELECT akey, total FROM families"):
            out[ak] = out.get(ak, 0) + total
        return out
    finally:
        conn.close()


def index_info():
    conn = open_ro()
    if conn is None:
        return {"ready": False}
    try:
        return {"ready": True, "built_at": _meta(conn, "built_at"), "families": int(_meta(conn, "families", "0") or 0),
                "last_rowid": int(_meta(conn, "last_rowid", "0") or 0),
                "mtime": os.path.getmtime(INDEX_PATH)}
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(description="恶意家族索引（output/family_index.db）")
    ap.add_argument("--full", action="store_true", help="全量重建")
    ap.add_argument("--db", default="", help="主库路径（默认 config.ini）")
    ap.add_argument("--stats", action="store_true", help="显示索引状态")
    args = ap.parse_args()
    if args.stats:
        print(json.dumps(index_info(), ensure_ascii=False, indent=2))
        return 0
    print("=" * 60)
    print("  恶意家族索引 →", INDEX_PATH)
    print("=" * 60)
    build(full=args.full, src_path=args.db)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
