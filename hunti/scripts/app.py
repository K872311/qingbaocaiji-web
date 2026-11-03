"""
威胁情报中心 Web 面板

情报数据直接查 ioc_data.db（只读）：
  1. 环境变量 HUNTI_WEB_DB
  2. 本脚本同目录下的 ioc_data.db（config.ini 的 ioc_db_path 也指向它，采集写的就是这个库）
  3. config/config.ini 里的 ioc_db_path
文章与暗网动态读 output/intel/*.json，用于给 IOC 关联出处。

启动:
  python -X utf8 app.py            # 默认监听 0.0.0.0:5000（局域网可访问）
  set HUNTI_WEB_HOST=127.0.0.1 && python -X utf8 app.py   # 仅本机
  set HUNTI_WEB_PORT=8080 && python -X utf8 app.py
"""
import glob
import json
import os
import re
import socket
import sqlite3
import threading
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote as url_quote, urlparse

from flask import Flask, jsonify, render_template, request

import family_index as fidx
from crawler_utils import extract_iocs, is_report_host, is_valid_domain, refang_text, sanitize_ioc_dict

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPTS_DIR)
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
INTEL_DIR = os.path.join(OUTPUT_DIR, "intel")
USER_INTEL_PATH = os.path.join(INTEL_DIR, "user_iocs.json")
_user_intel_lock = threading.Lock()

app = Flask(__name__, template_folder="templates", static_folder="static")
app.json.ensure_ascii = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

TYPE_LABELS = {"ip": "IP", "domain": "域名", "url": "URL", "file_hash": "文件哈希"}
SEARCH_LIMIT = 300
MAX_QUERY_LEN = 512
QUERY_TIMEOUT_S = 8
KEYWORD_PER_MINUTE = 20
KEYWORD_CONCURRENCY = 2
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class BadRequest(ValueError):
    pass


def _int_arg(name, default, lo, hi):
    raw = request.args.get(name, "")
    if raw == "":
        return default
    # 位数按上限自适应（since 等 Unix 时间戳可达 10 位）
    max_len = max(len(str(int(hi))), len(str(int(lo))), 1)
    if not re.fullmatch(r"\d{1,%d}" % max_len, raw):
        raise BadRequest("参数 {} 必须是非负整数".format(name))
    return max(lo, min(int(raw), hi))


def safe_http_url(u):
    """只放行 http / https，防止 javascript: 之类的链接落到页面上。"""
    u = (u or "").strip()
    return u if re.match(r"^https?://[^\s<>\"']+$", u, re.I) else ""


def resolve_db_path():
    """优先本目录的 ioc_data.db；config.ini 的 ioc_db_path 也指向它，采集与面板读写同一个库。"""
    env = os.environ.get("HUNTI_WEB_DB", "").strip()
    if env:
        return os.path.abspath(env)
    local = os.path.join(SCRIPTS_DIR, "ioc_data.db")
    if os.path.isfile(local):
        return local
    try:
        from export_to_db import resolve_db_path as pipeline_db
        return pipeline_db()
    except Exception:
        return local


DB_PATH = resolve_db_path()
fidx.EXPECTED_SRC = DB_PATH


def _decode_text(b):
    """库里有少量其他工具用 GBK 写入的字段，严格 UTF-8 解码会让整条查询失败。"""
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return b.decode("gbk")
        except UnicodeDecodeError:
            return b.decode("utf-8", "replace")


_READ_OK = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
_ALLOWED_TABLES = {"ioc_records"}


def _authorizer(action, arg1, arg2, dbname, source):
    """只允许读 ioc_records：即使将来有人拼错 SQL，也执行不了写入、ATTACH、PRAGMA。"""
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        return sqlite3.SQLITE_OK if arg1 in _ALLOWED_TABLES else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION:
        return sqlite3.SQLITE_OK if (arg2 or "").lower() in ("like", "count", "lower", "max", "min") else sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_DENY


def db(timeout_s=None):
    """每次请求单独开只读连接：sqlite 连接不能跨线程共用。"""
    uri = "file:{}?mode=ro".format(DB_PATH.replace("\\", "/"))
    conn = sqlite3.connect(uri, uri=True, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA query_only = ON")
    conn.row_factory = sqlite3.Row
    conn.text_factory = _decode_text
    conn.set_authorizer(_authorizer)
    deadline = time.time() + (QUERY_TIMEOUT_S if timeout_s is None else max(1, float(timeout_s)))
    conn.set_progress_handler(lambda: 1 if time.time() > deadline else 0, 20000)
    return conn


def _rows(cur):
    return [dict(r) for r in cur.fetchall()]


MAX_TAG_LEN = 40


def split_names(s):
    """库里的 malware / source 常是 "Akira; AsyncRAT; ClickFix" 这种拼接串，拆成单个名字；过长的多半是文章标题，丢掉。"""
    out = []
    for part in re.split(r"\s*[;|]\s*|,\s+", str(s or "")):
        part = part.strip().strip("[]'\"")
        if 2 <= len(part) <= MAX_TAG_LEN and part not in out:
            out.append(part)
    return out


def normalize_source(s):
    """早期工具把文章网址、"微步在线 | 标题"、"a, b"、"a; b" 直接写进 source，展示时归并成站点名。"""
    s = (s or "").strip()
    if not s:
        return ""
    s = re.split(r"\s*[|;]\s*|,\s+", s)[0].strip()
    if re.match(r"^https?://", s, re.I):
        s = (urlparse(s).hostname or s).lower()
    if s.startswith("www."):
        s = s[4:]
    return s


# ============================================================
# 情报文章（rss / url）与暗网动态（tc），给 IOC 关联出处
# ============================================================
_intel = {"articles": [], "darkweb": [], "by_ioc": {}, "by_alias": {}, "rl_groups": {}, "sig": None}
_intel_lock = threading.Lock()


def _to_dt(*values):
    for v in values:
        s = (v or "").strip()
        if not s:
            continue
        try:
            dt = parsedate_to_datetime(s)
        except (TypeError, ValueError, IndexError):
            try:
                dt = datetime.fromisoformat(re.sub(r"\.\d+", "", s.replace("Z", "+00:00"))[:25])
            except ValueError:
                continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    return None


# 文章类情报：(类别, glob, 解析方式)。路径都在 run_all 各步骤的产出目录里。
CATEGORIES = {
    "blog": "安全博客", "tc": "威胁通报", "otx": "OTX 情报包",
    "campaign": "战役报告", "apt": "APT 研究", "research": "恶意软件研究",
    "tf": "ThreatFox 引用", "yara": "YARA 规则", "malpedia": "Malpedia 文献",
}
# 专项主题：run_all 产出后由面板加载时按来源类别 + 标题/标签关键词自动归类（无需改爬虫）
TOPICS = {
    "apt": "APT",
    "c2": "C2",
    "cybercrime": "黑产",
    "ransomware": "勒索",
}
_TOPIC_KW = {
    "apt": (
        r"\bapt(?:[\s\-_]?\d+|[a-z]+)?\b", r"threat[\s\-]?actor", r"nation[\s\-]?state",
        r"高级持续", r"定向攻击", r"国家级", r"lazarus", r"sandworm", r"fancy[\s\-]?bear",
        r"cozy[\s\-]?bear", r"equation[\s\-]?group", r"winnti", r"mustang[\s\-]?panda",
    ),
    "c2": (
        r"\bc2\b", r"c\s*&\s*c", r"command[\s\-]?and[\s\-]?control", r"cobalt[\s\-]?strike",
        r"\bsliver\b", r"\bmythic\b", r"\bbeacon\b", r"团队服务器", r"恶意基础设施",
        r"c2[\s\-]?server", r"c2[\s\-]?infra", r"panel\b.*rat", r"\brat\b.*panel",
    ),
    "cybercrime": (
        r"stealer", r"infostealer", r"phishing", r"钓鱼",
        r"clickfix", r"初始访问", r"initial[\s\-]?access", r"黑产", r"地下黑市", r"botnet",
        r"loader", r"as[\s\-]?a[\s\-]?service", r"phaas", r"infostealer",
        r"bank(?:ing)?[\s\-]?trojan", r"盗号", r"刷单", r"黑灰产",
    ),
    "ransomware": (
        r"ransomware", r"勒索", r"ransom(?:ware)?", r"\braas\b", r"lockbit", r"clop\b",
        r"blackcat", r"alphv", r"play\s*ransomware", r"akira", r"qilin", r"双敲",
        r"double[\s\-]?extortion", r"leak[\s\-]?site", r"泄露站",
    ),
}
_TOPIC_RE = {k: re.compile("|".join("(?:%s)" % p for p in pats), re.I) for k, pats in _TOPIC_KW.items()}
# 不参与“热门标签”统计：文献库和规则库数量大、标签是分类关键字，会淹没近期情报
_HOT_TAG_SKIP = {"malpedia", "yara"}
# ThreatFox reference 里大量是工具 / 查询页面，不是报告
_TF_TOOL_HOSTS = (
    "threatfox.abuse.ch", "bazaar.abuse.ch", "urlhaus.abuse.ch", "virustotal.com", "tria.ge", "shodan.io",
    "censys.io", "censys.com", "twitter.com", "x.com", "github.com", "githubusercontent.com", "honeylabs.net",
    "threatview.io", "any.run", "urlscan.io", "urlquery.net", "otx.alienvault.com", "hybrid-analysis.com",
    "joesandbox.com", "validin.com", "fofa.info", "hunt.io", "bsky.app", "infosec.exchange", "t.me",
    "pastebin.com", "modat.io", "viriback.com", "polygonscan.com", "etherscan.io", "bscscan.com",
    "clickfixed.uk", "carsonww.com", "threatcluster.io", "linkedin.com", "youtube.com",
)
INTEL_SOURCES = [
    ("blog", os.path.join(INTEL_DIR, "rss_intel_*.json"), "article"),
    ("blog", os.path.join(INTEL_DIR, "url_intel_*.json"), "article"),
    ("apt", os.path.join(OUTPUT_DIR, "history", "apt", "intelligence_*.json"), "article"),
    ("research", os.path.join(SCRIPTS_DIR, "derp_research_*.json"), "article"),
    ("tc", os.path.join(INTEL_DIR, "tc_intel_*.json"), "tc_news"),
    ("otx", os.path.join(OUTPUT_DIR, "iocs", "otx_iocs_*.json"), "ioc_rows"),
    ("campaign", os.path.join(OUTPUT_DIR, "iocs", "thl_iocs_*.json"), "ioc_rows"),
    ("tc", os.path.join(OUTPUT_DIR, "iocs", "tc_iocs_*.json"), "ioc_rows"),
    ("research", os.path.join(OUTPUT_DIR, "history", "derp", "*.json"), "derp_rows"),
    ("tf", os.path.join(OUTPUT_DIR, "iocs", "tf_iocs_*.json"), "tf_refs"),
    ("yara", os.path.join(OUTPUT_DIR, "iocs", "valhalla_successful_rules_*.csv"), "valhalla"),
    ("yara", os.path.join(OUTPUT_DIR, "valhalla_new_iocs_*.csv"), "valhalla"),
    ("malpedia", os.path.join(OUTPUT_DIR, "malpedia.bib"), "bib"),
]
_IOC_KEYS = {"ip", "domain", "url", "md5", "sha1", "sha256"}


def _intel_files():
    out = []
    for cat, pattern, kind in INTEL_SOURCES:
        for path in sorted(glob.glob(pattern)):
            out.append((cat, path, kind))
    return out


def _intel_signature():
    files = [p for _, p, _ in _intel_files()] + glob.glob(os.path.join(INTEL_DIR, "rl_*.json"))
    if os.path.isfile(ETDA_FILE):
        files.append(ETDA_FILE)
    return len(files), max((os.path.getmtime(f) for f in files), default=0)


# ============================================================
# ETDA Threat Group Cards：APT 组织别名库（etda_loader.py 下载）
# ============================================================
ETDA_FILE = os.path.join(INTEL_DIR, "etda_groups.json")
ETDA_CARD_URL = "https://apt.etda.or.th/cgi-bin/showcard.cgi?g={}"
_ALIAS_SEP = re.compile(r"[\s\-_.]+")
# 普通英文单词 / 常见产品名，单独出现多半不是在说该组织；组织的其他别名照常匹配
_ALIAS_STOP = {
    "achilles", "aluminum", "axiom", "bitter", "boron", "bromine", "calcium", "casper", "cerium",
    "chimera", "chromium", "circles", "cron", "electrum", "elfin", "flea", "hades", "hermit", "iron",
    "karma", "krypton", "lead", "lookback", "lurk", "mantis", "mask", "mercury", "monsoon", "neon",
    "nickel", "nitro", "oxygen", "panda", "platinum", "popeye", "pupa", "reaper", "safe", "sandman",
    "scarab", "scimitar", "silence", "silicon", "sodium", "sphinx", "superman", "tick", "vendetta",
    "wildcard", "wraith", "zinc", "netsec", "indra", "siesta",
}
_etda = {"mtime": None, "groups": [], "by_key": {}, "title_re": None}
_etda_lock = threading.Lock()


def _alias_key(name):
    return _ALIAS_SEP.sub("", (name or "").lower())


def _alias_usable(name):
    key = _alias_key(name)
    return len(key) >= 4 and key not in _ALIAS_STOP


def _alias_distinctive(name):
    """不看上下文也不怕误伤的别名：带数字（APT 28、TA505）或多个词（Fancy Bear）。"""
    return _alias_usable(name) and (bool(re.search(r"\d", name)) or len(_ALIAS_SEP.split(name.strip())) >= 2)


def _alias_pattern(name):
    tokens = [re.escape(t) for t in _ALIAS_SEP.split(name.strip()) if t]
    return r"(?<![a-z0-9])" + r"[\s\-_.]?".join(tokens) + r"(?![a-z0-9])"


def load_etda():
    try:
        mtime = os.path.getmtime(ETDA_FILE)
    except OSError:
        mtime = None
    with _etda_lock:
        if _etda["mtime"] == mtime:
            return _etda
        groups, by_key, distinct = [], {}, []
        data = {}
        if mtime:
            try:
                with open(ETDA_FILE, encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, ValueError):
                data = {}
        for g in data.get("groups") or []:
            names = [n for n in g.get("names") or [] if n]
            if not names:
                continue
            motiv = " ".join(g.get("motivation") or []).lower()
            # ETDA 也收 FIN7 这类纯金融犯罪团伙：只有间谍 / 破坏动机或有归属国的才算 APT
            state = ("espionage" in motiv or "sabotage" in motiv) or (not motiv and bool(g.get("country")))
            usable = [n for n in names if _alias_usable(n)]
            # "Lazarus Group" 在文章里常只写 "Lazarus"
            for n in list(usable):
                short = re.sub(r"[\s\-_]+(?:group|team|gang)$", "", n, flags=re.I)
                if short != n and _alias_usable(short) and len(_alias_key(short)) >= 5 and short not in usable:
                    usable.append(short)
            idx = len(groups)
            groups.append({
                "name": g.get("name") or names[0], "card": g.get("card") or g.get("name") or names[0],
                "names": names, "country": g.get("country") or [],
                "motivation": g.get("motivation") or [], "first_seen": g.get("first_seen") or "",
                "description": g.get("description") or "", "state": state,
                "keys": {_alias_key(n) for n in usable},
                # 标题匹配用的小写别名；短单词用空格边界，避免 "safe" 误伤
                "title_needles": [
                    (n.lower(), _alias_distinctive(n) or (len(_ALIAS_SEP.split(n.strip())) >= 2) or bool(re.search(r"\d", n)))
                    for n in usable
                ],
            })
            for n in usable:
                by_key.setdefault(_alias_key(n), idx)
        _etda.update({"mtime": mtime, "groups": groups, "by_key": by_key})
        return _etda


def etda_group(name):
    e = load_etda()
    idx = e["by_key"].get(_alias_key(name))
    return e["groups"][idx] if idx is not None else None


def _etda_groups_in(a):
    """文章涉及的 ETDA 组织：只看已提取的团伙标签，不扫标题（全库扫一遍要几十秒）。"""
    e = load_etda()
    found = set()
    for x in a.get("actors") or []:
        idx = e["by_key"].get(_alias_key(x))
        if idx is not None:
            found.add(idx)
    return [e["groups"][i] for i in found]


def _article_matches_group(a, g):
    if any(_alias_key(x) in g["keys"] for x in (a.get("actors") or []) + (a.get("malware") or [])):
        return True
    title = " {} ".format((a.get("title") or "").lower())
    for needle, distinctive in g["title_needles"]:
        if distinctive:
            if needle in title:
                return True
        elif " {} ".format(needle) in title:
            return True
    return False


def _etda_public(g):
    return {
        "name": g["name"], "names": g["names"], "country": g["country"], "motivation": g["motivation"],
        "first_seen": g["first_seen"], "description": g["description"][:800],
        "url": ETDA_CARD_URL.format(url_quote(g["card"])),
        "source": "ETDA Threat Group Cards",
    }


def _as_list(v):
    if isinstance(v, list):
        return v
    if isinstance(v, str) and v.startswith("["):
        try:
            import ast
            x = ast.literal_eval(v)
            return x if isinstance(x, list) else []
        except (ValueError, SyntaxError):
            return []
    return [v] if v else []


def _file_dt(path):
    m = re.search(r"(\d{8})_(\d{6})", os.path.basename(path))
    if m:
        try:
            return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)


def _load_csv_rows(path):
    import csv
    try:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
            return list(csv.DictReader(fh))
    except OSError:
        return []


_BIB_ENTRY = re.compile(r"@\w+\{([^,\n]+),\s*\n(.*?)\n\}", re.S)
_BIB_FIELD = re.compile(r"^\s*(\w+)\s*=\s*\{(.*)\},?\s*$", re.M)


def _load_bib(path):
    """Malpedia 的 BibTeX：@online{org:yyyymmdd:keyword:hash, title={{...}}, date=..., url=...}"""
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    out = []
    for key, body in _BIB_ENTRY.findall(text):
        f = {k.lower(): v.strip().strip("{}").strip() for k, v in _BIB_FIELD.findall(body)}
        parts = key.split(":")
        f["_keyword"] = parts[2] if len(parts) >= 4 else ""
        out.append(f)
    return out


_TAG_STOP = {
    "none", "null", "unknown", "n/a", "na", "other", "misc", "generic", "malware", "threat", "report", "analysis",
    "joint", "linux", "windows", "android", "macos", "ios", "apt", "attack", "attacks", "campaign", "operation",
    "new", "the", "from", "with", "update", "advisory", "research", "blog", "part", "how", "what", "inside",
    "ransomware", "stealer", "loader", "backdoor", "trojan", "botnet", "phishing", "spyware", "rat", "c2",
}


def _is_binary_text(s):
    """APT 历史采集里有把 PDF / 压缩流当正文存下来的，摘要和从中抽的 IOC 都是噪音。"""
    head = str(s or "")[:600]
    if not head:
        return False
    if head.lstrip().startswith(("%PDF", "PK\x03\x04", "\x1f\x8b")):
        return True
    bad = sum(1 for ch in head if ch == "\ufffd" or (ord(ch) < 32 and ch not in "\r\n\t"))
    return bad / len(head) > 0.03


def _bad_title(t, url=""):
    t = (t or "").strip()
    return not t or t == url or t.startswith("/") or bool(re.fullmatch(r"[\w./%-]+\.(pdf|html?|php|aspx?)", t, re.I))


def _good_tag(x):
    s = str(x or "").strip()
    return len(s) >= 3 and s.lower() not in _TAG_STOP


def _looks_like_report(url):
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if not host or any(host == t or host.endswith("." + t) for t in _TF_TOOL_HOSTS):
        return False
    if p.query:
        return False
    path = p.path.strip("/")
    if not path:
        return False
    last = path.split("/")[-1]
    return last.count("-") >= 2 or bool(re.search(r"/(blog|research|posts?|p|articles?|threat-intel|labs)/", "/" + path + "/"))


def _load_json_list(path):
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return []
    if isinstance(data, dict):
        data = next((v for v in data.values() if isinstance(v, list)), [])
    return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []


def _collect_articles():
    """把 run_all 各步骤产出的文章 / 情报包 / 报告合并成一张表，按 URL 去重并合并 IOC。"""
    by_url = {}

    def add(cat, url, title, source, dt, actors=(), malware=(), iocs=None, summary=""):
        url = safe_http_url(url)
        if not url:
            return
        a = by_url.get(url)
        if a is None:
            a = by_url[url] = {
                "title": "", "url": url, "source": "", "cat": cat, "cats": [],
                "date": "", "_ts": 0, "actors": [], "malware": [], "iocs": {}, "summary": "",
            }
        if cat not in a["cats"]:
            a["cats"].append(cat)
        if title and not _bad_title(str(title), url) and (_bad_title(a["title"], url) or a["cat"] == cat):
            a["title"] = str(title)[:300]
        elif title and not a["title"]:
            a["title"] = str(title)[:300]
        if source and not a["source"]:
            a["source"] = str(source)[:80]
        if summary and not a["summary"] and not _is_binary_text(summary):
            a["summary"] = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", str(summary)))[:280]
        if dt and (not a["_ts"] or dt.timestamp() < a["_ts"]):
            a["_ts"] = dt.timestamp()
            a["date"] = dt.strftime("%Y-%m-%d")
        a["actors"] = _uniq(a["actors"] + [n for x in _as_list(actors) for n in split_names(x) if _good_tag(n)])[:12]
        a["malware"] = _uniq(a["malware"] + [n for x in _as_list(malware) for n in split_names(x) if _good_tag(n)])[:12]
        cleaned = sanitize_ioc_dict(
            {t: vals for t, vals in (iocs or {}).items() if t in _IOC_KEYS},
            article_url=url,
        )
        for t, vals in cleaned.items():
            bucket = a["iocs"].setdefault(t, [])
            seen = {x.lower() for x in bucket}
            for v in vals:
                if v.lower() not in seen and len(bucket) < 200:
                    bucket.append(v)
                    seen.add(v.lower())

    for cat, path, kind in _intel_files():
        fdt = _file_dt(path)
        if kind == "bib":
            for r in _load_bib(path):
                dt = _to_dt(r.get("date")) or _to_dt(r.get("urldate"))
                kw = r.get("_keyword") or ""
                org = r.get("organization") or r.get("author") or ""
                summary = " · ".join(x for x in (
                    "作者：" + r["author"] if r.get("author") else "",
                    "机构：" + r["organization"] if r.get("organization") else "",
                    "语言：" + r["language"] if r.get("language") else "") if x)
                add(cat, r.get("url"), r.get("title"), org, dt, malware=[kw], summary=summary)
            continue
        if kind == "valhalla":
            grouped = {}
            for r in _load_csv_rows(path):
                url, name = r.get("info_url"), r.get("rule_name")
                if not url or not name:
                    continue
                g = grouped.setdefault(url, {"name": name, "iocs": {}})
                t, v = (r.get("ioc_type") or "").lower(), r.get("ioc_value")
                if t and v:
                    g["iocs"].setdefault(t, []).append(v)
            for url, g in grouped.items():
                add(cat, url, "YARA 规则：" + g["name"], "Valhalla", fdt, malware=[g["name"]], iocs=g["iocs"],
                    summary="Nextron Valhalla 规则 {}，命中样本见 IOC 列表".format(g["name"]))
            continue
        rows = _load_json_list(path)
        if kind == "tf_refs":
            grouped = {}
            for r in rows:
                url = r.get("url") or ""
                if not url or not _looks_like_report(url):
                    continue
                g = grouped.setdefault(url, {"iocs": {}, "malware": [], "dt": None})
                t, v = (r.get("ioc_type") or "").lower(), r.get("ioc_value")
                if t and v:
                    g["iocs"].setdefault(t, []).append(v)
                g["malware"] += _as_list(r.get("malware"))
                d = _to_dt(r.get("first_seen"), r.get("crawl_time"))
                if d and (g["dt"] is None or d < g["dt"]):
                    g["dt"] = d
            for url, g in grouped.items():
                add(cat, url, None, "", g["dt"] or fdt, malware=g["malware"], iocs=g["iocs"],
                    summary="ThreatFox 收录的 IOC 引用了该报告")
            continue
        if kind == "article":
            for r in rows:
                iocs = r.get("iocs") if isinstance(r.get("iocs"), dict) else {}
                if _is_binary_text(r.get("content")):
                    iocs = {}
                dt = _to_dt(r.get("page_published"), r.get("published"), r.get("crawl_time")) or fdt
                src = r.get("source") or ("derp.ca" if cat == "research" else "")
                summary = r.get("summary") or (r.get("content") or "")[:400]
                add(cat, r.get("url"), r.get("title"), src, dt, r.get("threat_actors"), r.get("malware"), iocs, summary)
        elif kind == "tc_news":
            for r in rows:
                if "/dark-web" in (r.get("url") or ""):
                    continue
                dt = _to_dt(r.get("published"), r.get("crawl_time")) or fdt
                add(cat, r.get("url"), r.get("title"), "ThreatCluster", dt,
                    r.get("threat_actors"), r.get("malware"), None, r.get("content"))
        elif kind == "ioc_rows":
            grouped = {}
            for r in rows:
                url = r.get("url")
                t = (r.get("ioc_type") or "").lower()
                v = r.get("ioc_value")
                if not url or not v:
                    continue
                g = grouped.setdefault(url, {"r": r, "iocs": {}, "actors": [], "malware": []})
                g["iocs"].setdefault(t, []).append(v)
                g["actors"] += _as_list(r.get("threat_actors"))
                g["malware"] += _as_list(r.get("malware"))
            for url, g in grouped.items():
                r = g["r"]
                title, summary = r.get("title"), ""
                src = r.get("source") or ""
                if cat == "tc":
                    title, summary = None, r.get("title") or ""
                    src = (urlparse(url).hostname or src).replace("www.", "")
                dt = _to_dt(r.get("published"), r.get("crawl_time")) or fdt
                if cat == "otx" and r.get("author"):
                    src = "OTX · {}".format(r["author"])
                add(cat, url, title, src, dt, g["actors"], g["malware"], g["iocs"], summary)
        elif kind == "derp_rows":
            grouped = {}
            for r in rows:
                url = r.get("source_url")
                t = (r.get("type") or "").lower()
                if not url or not r.get("value"):
                    continue
                g = grouped.setdefault(url, {"title": r.get("source"), "iocs": {}})
                g["iocs"].setdefault(t, []).append(r["value"])
            for url, g in grouped.items():
                add(cat, url, g["title"], "derp.ca", fdt, iocs=g["iocs"])

    for a in by_url.values():
        if _bad_title(a["title"], a["url"]):
            a["title"] = _title_from_url(a["url"])
        if not a["source"]:
            a["source"] = (urlparse(a["url"]).hostname or "").replace("www.", "")
    return list(by_url.values())


def _title_from_url(url):
    """没有标题的报告（ThreatCluster 只给了 IOC 描述）用 URL 末段 slug 拼一个可读标题。"""
    p = urlparse(url)
    parts = [x for x in p.path.split("/") if x and not re.fullmatch(r"\d{1,4}|index\.html?|blog|post|posts", x, re.I)]
    slug = re.sub(r"\.(html?|php|aspx?)$", "", parts[-1]) if parts else ""
    words = re.sub(r"[-_+]+", " ", slug).strip()
    host = (p.hostname or "").replace("www.", "")
    if len(words) < 6 or re.fullmatch(r"[a-f0-9 ]{16,}", words):
        return "{} 情报".format(host or url)[:300]
    return (words[:1].upper() + words[1:])[:300]


def _dark_key(group, victim):
    return "{}|{}".format(re.sub(r"\s+", " ", (group or "").strip().lower()),
                          re.sub(r"\s+", " ", (victim or "").strip().lower()))


def _collect_darkweb():
    """暗网勒索事件：ThreatCluster（转载 ransomware.live）+ ransomware.live 直采，按 团伙|受害方 合并。"""
    dark = {}

    def put(key, entry, source):
        cur = dark.get(key)
        if cur is None:
            entry["sources"] = [source]
            dark[key] = entry
            return
        if source not in cur["sources"]:
            cur["sources"].append(source)
        for k, v in entry.items():
            if v and (not cur.get(k) or (source == "ransomware.live" and k not in ("date", "time", "_ts"))):
                cur[k] = v
        if entry.get("_ts") and (not cur.get("_ts") or entry["_ts"] < cur["_ts"]):
            cur["_ts"], cur["date"], cur["time"] = entry["_ts"], entry["date"], entry["time"]

    for path in sorted(glob.glob(os.path.join(INTEL_DIR, "tc_intel_*.json"))):
        for d in _load_json_list(path):
            url = d.get("url") or ""
            if "/dark-web" not in url:
                continue
            fields = dict(re.findall(r"(\w+)=(.*?)(?=\s+\w+=|$)", d.get("content") or ""))
            actors = d.get("threat_actors")
            group = (fields.get("group") or (actors[0] if isinstance(actors, list) and actors else "")).strip()
            victim = (fields.get("victim") or re.sub(r"\s+claimed by\s+.*$", "", d.get("title") or "")).strip()
            if not victim:
                continue
            dt = _to_dt(d.get("published"), d.get("crawl_time"))
            put(_dark_key(group, victim), {
                "victim": victim[:200], "group": group[:80],
                "country": (fields.get("country") or d.get("country") or "").strip()[:8],
                "sector": (fields.get("sector") or d.get("sector") or "").strip()[:60],
                "status": (fields.get("status") or "").strip()[:30],
                "tc_url": safe_http_url(url),
                "date": dt.strftime("%Y-%m-%d") if dt else "", "time": dt.strftime("%Y-%m-%d %H:%M") if dt else "",
                "_ts": dt.timestamp() if dt else 0,
            }, "ThreatCluster")

    for path in sorted(glob.glob(os.path.join(INTEL_DIR, "rl_victims_*.json"))):
        for v in _load_json_list(path):
            victim, group = (v.get("victim") or "").strip(), (v.get("group") or "").strip()
            if not victim:
                continue
            dt = _to_dt(v.get("discovered"))
            at = _to_dt(v.get("attackdate"))
            claim = (v.get("claim_url") or "").strip()
            put(_dark_key(group, victim), {
                "victim": victim[:200], "group": group[:80],
                "country": (v.get("country") or "")[:8], "sector": (v.get("activity") or "")[:60],
                "status": "listed",
                "domain": (v.get("domain") or "")[:200],
                "description": re.sub(r"\s+", " ", v.get("description") or "")[:600],
                "data_size": (v.get("data_size") or "")[:40], "ransom": (v.get("ransom") or "")[:60],
                "screenshot": safe_http_url(v.get("screenshot")),
                "rl_url": safe_http_url(v.get("url")),
                "leak_url": claim[:300] if ".onion" in claim else "",
                "press": safe_http_url(v.get("press")),
                "attack_date": at.strftime("%Y-%m-%d") if at and dt and at.date() != dt.date() else "",
                "date": dt.strftime("%Y-%m-%d") if dt else "", "time": dt.strftime("%Y-%m-%d %H:%M") if dt else "",
                "_ts": dt.timestamp() if dt else 0,
            }, "ransomware.live")

    items = sorted(dark.values(), key=lambda x: x["_ts"], reverse=True)[:20000]
    for i, d in enumerate(items):
        d["id"] = i
        d["title"] = "{} claimed by {}".format(d["victim"], d["group"])
        d["source_url"] = d.get("rl_url") or d.get("tc_url") or "https://www.ransomware.live/"
    return items


def _load_rl_groups():
    path = os.path.join(INTEL_DIR, "rl_groups.json")
    out = {}
    for g in _load_json_list(path):
        name = (g.get("name") or "").strip()
        if not name:
            continue
        tools = {}
        for block in g.get("tools") or []:
            if isinstance(block, dict):
                for cat, names in block.items():
                    if isinstance(names, list):
                        tools.setdefault(cat, []).extend(str(n)[:80] for n in names[:30])
        ttps = []
        for t in g.get("ttps") or []:
            if isinstance(t, dict):
                ttps.append({
                    "tactic": t.get("tactic_name") or t.get("tactic_id") or "",
                    "techniques": [{"id": x.get("technique_id", ""), "name": x.get("technique_name", ""),
                                    "details": (x.get("technique_details") or "")[:300]}
                                   for x in (t.get("techniques") or []) if isinstance(x, dict)][:20],
                })
        locs = [{"fqdn": (l.get("fqdn") or "")[:120], "title": (l.get("title") or "")[:80],
                 "type": l.get("type") or "", "available": bool(l.get("available"))}
                for l in (g.get("locations") or []) if isinstance(l, dict)][:20]
        alt = g.get("altname")
        out[name.lower()] = {
            "name": name, "altname": alt if isinstance(alt, str) and alt.lower() != "none" else "",
            "description": (g.get("description") or "")[:2000], "added_date": g.get("added_date") or "",
            "url": safe_http_url(g.get("url")), "tools": tools, "ttps": ttps, "locations": locs,
        }
    return out


def _article_topics(a):
    """按来源类别 + 标题/摘要/团伙/家族关键词自动打专项标签。"""
    topics = []
    cats = set(a.get("cats") or [])
    if "apt" in cats:
        topics.append("apt")
    blob = " ".join([
        a.get("title") or "", a.get("summary") or "", a.get("source") or "",
        " ".join(a.get("actors") or []), " ".join(a.get("malware") or []),
        " ".join(cats),
    ])
    for key, rx in _TOPIC_RE.items():
        if key in topics:
            continue
        if rx.search(blob):
            topics.append(key)
    for g in _etda_groups_in(a):
        key = "apt" if g["state"] else "cybercrime"
        if key not in topics:
            topics.append(key)
    low = blob.lower()
    # 战役 / 威胁通报默认归入黑产；含勒索关键词再打勒索标签
    if "cybercrime" not in topics and (cats & {"campaign", "tc"}):
        topics.append("cybercrime")
    if "ransomware" not in topics and any(x in low for x in ("ransomware", "勒索", "ransom", "leak site", "泄露站")):
        topics.append("ransomware")
    return topics


def load_intel(force=False):
    sig = _intel_signature()
    with _intel_lock:
        if _intel["sig"] == sig and not force:
            return
        t0 = time.time()
        articles = sorted(_collect_articles(), key=lambda x: x["_ts"], reverse=True)
        by_ioc = {}
        by_alias = {}
        topic_counts = {k: 0 for k in TOPICS}
        for idx, a in enumerate(articles):
            a["id"] = idx
            for x in (a.get("actors") or []) + (a.get("malware") or []):
                k = _alias_key(x)
                if len(k) >= 3:
                    by_alias.setdefault(k, set()).add(idx)
            a["iocs"] = sanitize_ioc_dict(a.get("iocs") or {}, article_url=a.get("url") or "")
            a["ioc_count"] = sum(len(v) for v in a["iocs"].values())
            a["ioc_types"] = {t: len(v) for t, v in a["iocs"].items() if v}
            a["cat_label"] = CATEGORIES.get(a["cat"], a["cat"])
            a["topics"] = _article_topics(a)
            for t in a["topics"]:
                topic_counts[t] = topic_counts.get(t, 0) + 1
            a["_blob"] = " ".join([a["title"], a["summary"], a["source"]] + a["actors"] + a["malware"]).lower()
            for vals in a["iocs"].values():
                for v in vals:
                    key = str(v).lower()
                    by_ioc.setdefault(key, []).append(idx)
                    if re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", key):
                        by_ioc.setdefault(key.split(":")[0], []).append(idx)

        darkweb = _collect_darkweb()
        rl_groups = _load_rl_groups()

        _intel.update({
            "articles": articles, "darkweb": darkweb, "by_ioc": by_ioc, "by_alias": by_alias,
            "rl_groups": rl_groups, "topic_counts": topic_counts, "sig": sig,
        })
        print("情报文章已加载: {} 篇，暗网动态 {} 条，专项 APT/C2/黑产/勒索 {}/{}/{}/{}，用时 {:.1f}s".format(
            len(articles), len(darkweb),
            topic_counts.get("apt", 0), topic_counts.get("c2", 0),
            topic_counts.get("cybercrime", 0), topic_counts.get("ransomware", 0),
            time.time() - t0))


def _uniq(items):
    seen, out = set(), []
    for x in items or []:
        k = str(x).strip().lower()
        if k and k not in seen:
            seen.add(k)
            out.append(str(x).strip())
    return out


def _article_brief(a):
    return {k: v for k, v in a.items() if k not in ("iocs", "_ts", "_blob")}


def articles_for(values):
    seen, out = set(), []
    for v in values:
        for idx in _intel["by_ioc"].get((v or "").lower(), []):
            if idx in seen:
                continue
            seen.add(idx)
            out.append(_article_brief(_intel["articles"][idx]))
    out.sort(key=lambda x: x["date"], reverse=True)
    return out[:50]


# ============================================================
# 搜索
# ============================================================
_IPV4 = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?$")
_HASH = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
HASH_NAMES = {32: "MD5", 40: "SHA1", 64: "SHA256"}


def refang(q):
    s = (q or "").strip().strip("'\"")
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":"), ("[://]", "://")):
        s = s.replace(a, b)
    return s.strip()


def detect(q):
    s = refang(q)
    low = s.lower()
    if _IPV4.match(s):
        return "ip", s
    if _HASH.match(low):
        return "file_hash", low
    if re.match(r"^[a-z][a-z0-9+.-]*://", low):
        return "url", low
    if _DOMAIN.match(low.rstrip(".")):
        return "domain", low.rstrip(".")
    return "keyword", s


COLS = "SELECT type, value, ip_only, source, malware FROM ioc_records "
SAMPLE_LIMIT = 80

_geo_reader = None
_geo_state = {"path": None, "ok": False, "tried": False}


def _geo_db_candidates():
    env = (os.environ.get("HUNTI_GEOIP_DB") or "").strip()
    return [p for p in (
        env,
        os.path.join(SCRIPTS_DIR, "geoip", "GeoLite2-City.mmdb"),
        os.path.join(SCRIPTS_DIR, "geoip", "GeoLite2-Country.mmdb"),
    ) if p]


def _get_geo_reader():
    """可选本地 MaxMind mmdb；无库或未安装 maxminddb 时返回 None。"""
    global _geo_reader
    if _geo_state["tried"]:
        return _geo_reader if _geo_state["ok"] else None
    _geo_state["tried"] = True
    path = next((p for p in _geo_db_candidates() if os.path.isfile(p)), "")
    if not path:
        return None
    try:
        import maxminddb
        _geo_reader = maxminddb.open_database(path)
        _geo_state.update({"path": path, "ok": True})
        print("GeoIP 已加载:", path)
        return _geo_reader
    except Exception as e:
        print("GeoIP 加载失败:", e)
        _geo_reader = None
        _geo_state["ok"] = False
        return None


def lookup_geo(ip):
    """返回 {country, region, city, label}；未配置库时返回 None。"""
    if not ip or not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
        return None
    reader = _get_geo_reader()
    if not reader:
        return None
    try:
        rec = reader.get(ip)
    except Exception:
        return None
    if not rec:
        return None
    country = ((rec.get("country") or {}).get("names") or {}).get("zh-CN") \
        or ((rec.get("country") or {}).get("names") or {}).get("en") \
        or (rec.get("country") or {}).get("iso_code") or ""
    region = ""
    subs = rec.get("subdivisions") or []
    if subs:
        region = (subs[0].get("names") or {}).get("zh-CN") or (subs[0].get("names") or {}).get("en") or ""
    city = ((rec.get("city") or {}).get("names") or {}).get("zh-CN") \
        or ((rec.get("city") or {}).get("names") or {}).get("en") or ""
    parts = [p for p in (country, region, city) if p]
    if not parts:
        return None
    return {"country": country, "region": region, "city": city, "label": " · ".join(parts)}


def _rows_by_rowid(conn, rids):
    """按家族索引给出的 rowid 回主库取行，保持 rids 的顺序（新→旧）。"""
    out = []
    rids = [int(r) for r in rids or []]
    for i in range(0, len(rids), 400):
        chunk = rids[i:i + 400]
        rows = conn.execute(
            "SELECT rowid AS rid, type, value, ip_only, source, malware FROM ioc_records WHERE rowid IN ({})".format(
                ",".join("?" * len(chunk))), chunk).fetchall()
        by = {r["rid"]: {k: r[k] for k in ("type", "value", "ip_only", "source", "malware")} for r in rows}
        out += [by[r] for r in chunk if r in by]
    return out


def _keyword_families(kw):
    """关键词 → 家族索引条目；关键词是 APT 别名时带上该组织全部别名。"""
    try:
        grp = etda_group(kw)
        if grp:
            fams = fidx.families_by_akeys(set(grp["keys"]) | {_alias_key(kw)})
            if fams:
                return fams
        return fidx.find_families(kw) or []
    except Exception as e:
        app.logger.warning("family index lookup failed: %s", e)
        return []


def _related_samples(conn, families, exclude_values, limit=SAMPLE_LIMIT):
    """同恶意家族的文件哈希样本（本地库）。

    不用 '%name%' 全表扫描（500 万行会超时），只做精确 / 前缀匹配：
    malware = name 或 name;... / name|... / name, ...
    """
    fams = [f for f in (families or []) if len(f) >= 3][:5]
    if not fams:
        return []
    exclude = {str(v).lower() for v in (exclude_values or [])}
    out, seen = [], set()
    if fidx.index_info().get("ready"):
        rids = fidx.rowids_for([f.lower() for f in fams], types=["file_hash"], limit=limit + len(exclude) + 20)
        for r in _rows_by_rowid(conn, rids):
            val = (r.get("value") or "").lower()
            if not val or val in exclude or val in seen:
                continue
            seen.add(val)
            r["families"] = split_names(r.get("malware"))
            out.append(r)
            if len(out) >= limit:
                break
        return out
    for fam in fams:
        esc = fam.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        rows = _rows(conn.execute(
            COLS + "WHERE type = 'file_hash' AND ("
            "malware = ? OR malware LIKE ? ESCAPE '\\' OR malware LIKE ? ESCAPE '\\' "
            "OR malware LIKE ? ESCAPE '\\') LIMIT 120",
            (fam, esc + ";%", esc + "|%", esc + ", %"),
        ))
        fl = fam.lower()
        for r in rows:
            val = (r.get("value") or "").lower()
            if not val or val in exclude or val in seen:
                continue
            names = {n.lower() for n in split_names(r.get("malware"))}
            if fl not in names:
                continue
            seen.add(val)
            r["families"] = split_names(r.get("malware"))
            out.append(r)
            if len(out) >= limit:
                return out
    return out


def _prefix_range(conn, type_, prefix, limit=500):
    return _rows(conn.execute(
        COLS + "WHERE type = ? AND value >= ? AND value < ? LIMIT ?",
        (type_, prefix, prefix + "\uffff", limit),
    ))


def _urls_on_host(conn, host):
    out = []
    for scheme in ("http://", "https://"):
        for r in _prefix_range(conn, "url", scheme + host):
            h = (urlparse(r["value"]).hostname or "").lower()
            if h == host:
                out.append(r)
    return out[:200]


def _dedupe(rows):
    seen, out = set(), []
    for r in rows:
        k = (r["type"], r["value"])
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def search(q):
    kind, norm = detect(q)
    res = {"normalized": norm, "kind": kind, "kind_label": TYPE_LABELS.get(kind, "关键词"),
           "records": [], "related_urls": [], "parent_domains": [], "related_samples": [],
           "ports": [], "geo": None, "ip_enrich": None, "profile_records": [], "truncated": False}
    if kind == "file_hash":
        res["kind_label"] = HASH_NAMES.get(len(norm), "文件哈希")
    values = [norm]
    conn = db()
    try:
        if kind == "ip":
            ip = _IPV4.match(norm).group(1)
            rows = _rows(conn.execute(COLS + "WHERE ip_only = ? LIMIT ?", (ip, SEARCH_LIMIT)))
            rows += _rows(conn.execute(COLS + "WHERE type = 'ip' AND value = ?", (norm,)))
            res["records"] = rows
            res["related_urls"] = _urls_on_host(conn, ip)
            res["ip"] = ip
            res["geo"] = lookup_geo(ip)
            try:
                from ip_enrich import lookup as ip_enrich_lookup
                res["ip_enrich"] = ip_enrich_lookup(ip)
            except Exception as e:
                res["ip_enrich"] = {"tags": [], "flags": {}, "summary": "", "loaded": False, "error": str(e)}
            values = [ip, norm]
        elif kind == "file_hash":
            res["records"] = _rows(conn.execute(COLS + "WHERE type = 'file_hash' AND value = ?", (norm,)))
        elif kind == "domain":
            res["records"] = _rows(conn.execute(COLS + "WHERE type = 'domain' AND value = ?", (norm,)))
            labels = norm.split(".")
            for p in [".".join(labels[i:]) for i in range(1, len(labels) - 1)]:
                res["parent_domains"] += _rows(conn.execute(COLS + "WHERE type = 'domain' AND value = ?", (p,)))
            res["related_urls"] = _urls_on_host(conn, norm)
        elif kind == "url":
            res["records"] = _rows(conn.execute(COLS + "WHERE type = 'url' AND value = ?", (norm,)))
            host = (urlparse(norm).hostname or "").lower()
            if host:
                if _IPV4.match(host):
                    res["parent_domains"] = _rows(conn.execute(COLS + "WHERE ip_only = ? LIMIT 50", (host,)))
                    res["geo"] = lookup_geo(host)
                    try:
                        from ip_enrich import lookup as ip_enrich_lookup
                        res["ip_enrich"] = ip_enrich_lookup(host)
                    except Exception as e:
                        res["ip_enrich"] = {"tags": [], "flags": {}, "summary": "", "loaded": False, "error": str(e)}
                else:
                    res["parent_domains"] = _rows(conn.execute(
                        COLS + "WHERE type = 'domain' AND value = ?", (host,)))
                res["related_urls"] = [r for r in _urls_on_host(conn, host) if r["value"] != norm]
                res["host"] = host
                values = [norm, host]
        else:
            if len(norm) < 3:
                res["error"] = "关键词至少 3 个字符"
                return res
            fams = _keyword_families(norm)
            if fams:
                rows = _rows_by_rowid(conn, fidx.rowids_for([f["key"] for f in fams[:20]], limit=SEARCH_LIMIT))
                total = sum(f["total"] for f in fams[:20])
                res["family_matches"] = [{k: f[k] for k in ("name", "total", "counts")} for f in fams[:12]]
                res["family_total"] = total
                res["truncated"] = total > len(rows)
                res["via_index"] = True
            else:
                like = "%{}%".format(norm.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_"))
                rows = _rows(conn.execute(
                    COLS + "WHERE malware LIKE ? ESCAPE '\\' OR value LIKE ? ESCAPE '\\' LIMIT ?",
                    (like, like, SEARCH_LIMIT)))
                res["truncated"] = len(rows) >= SEARCH_LIMIT
            res["records"] = rows
            values = []

        # ip_profile = 入库的 IP 画像（云/CDN/VPN/Tor/代理/DNS 属性），不是恶意 IOC
        res["profile_records"] = _dedupe([r for r in res["records"] + res["parent_domains"]
                                          if r["type"] == "ip_profile"])
        res["records"] = _dedupe([r for r in res["records"] if r["type"] != "ip_profile"])
        res["parent_domains"] = _dedupe([r for r in res["parent_domains"] if r["type"] != "ip_profile"])
        if kind == "ip":
            res["ports"] = sorted({r["value"].split(":")[1] for r in res["records"]
                                   if r["type"] == "ip" and r["value"].count(":") == 1}, key=lambda p: int(p))

        fam, src = {}, {}
        for r in res["records"] + res["parent_domains"]:
            r["families"] = split_names(r.get("malware"))
            for name in r["families"]:
                fam[name] = fam.get(name, 0) + 1
            name = normalize_source(r.get("source"))
            if name and len(name) <= MAX_TAG_LEN:
                src[name] = src.get(name, 0) + 1
        for r in res["related_urls"]:
            r["families"] = split_names(r.get("malware"))
        res["families"] = sorted(fam.items(), key=lambda x: -x[1])[:20]
        res["sources"] = sorted(src.items(), key=lambda x: -x[1])[:20]

        # 关联样本不在主查询里跑（malware 无合适索引，扫数百万行会超时），
        # 由 /api/related_samples 异步加载；关键词命中里的哈希可直接展示。
        res["related_samples"] = []
        res["sample_families"] = [n for n, _ in res["families"][:8]]
    finally:
        conn.close()

    # 合并用户手工提交的 IOC（不写主库）
    user_hits = match_user_iocs(kind, norm)
    if user_hits:
        for r in user_hits:
            r["families"] = r.get("families") or split_names(r.get("malware"))
        res["records"] = _dedupe(res["records"] + user_hits)
        fam, src = {}, {}
        for r in res["records"] + res["parent_domains"]:
            for name in r.get("families") or split_names(r.get("malware")):
                fam[name] = fam.get(name, 0) + 1
            name = normalize_source(r.get("source"))
            if name and len(name) <= MAX_TAG_LEN:
                src[name] = src.get(name, 0) + 1
        res["families"] = sorted(fam.items(), key=lambda x: -x[1])[:20]
        res["sources"] = sorted(src.items(), key=lambda x: -x[1])[:20]
        res["sample_families"] = [n for n, _ in res["families"][:8]]
        if res["records"]:
            res["verdict"] = "malicious"

    if kind == "keyword":
        kw = norm.lower()
        grp = etda_group(norm)
        if grp:
            res["actor_profile"] = _etda_public(grp)
        hits = [a for a in _intel["articles"]
                if kw in a["title"].lower()
                or any(kw in str(x).lower() for x in a["actors"] + a["malware"])
                or (grp and _article_matches_group(a, grp))]
        res["articles"] = [_article_brief(a) for a in hits[:50]]
        hashes = [r for r in res["records"] if r.get("type") == "file_hash"]
        for r in hashes:
            r["families"] = split_names(r.get("malware"))
        res["related_samples"] = hashes[:SAMPLE_LIMIT]
        if not res.get("sample_families") and norm:
            res["sample_families"] = [norm]
    else:
        res["articles"] = articles_for([v for v in values if v])
    res["sample_exclude"] = [r["value"] for r in res["records"] if r.get("type") == "file_hash"]
    if kind == "file_hash":
        res["sample_exclude"] = list(set(res["sample_exclude"] + [norm]))
    res["user_hits"] = len(user_hits)

    tags = {}
    for a in res["articles"]:
        for t in a["actors"]:
            tags.setdefault(("actor", t), 0)
            tags[("actor", t)] += 1
        for t in a["malware"]:
            tags.setdefault(("malware", t), 0)
            tags[("malware", t)] += 1
    for name, c in res["families"]:
        tags[("malware", name)] = tags.get(("malware", name), 0) + c
    res["tags"] = [{"kind": k, "name": n, "count": c}
                   for (k, n), c in sorted(tags.items(), key=lambda x: -x[1])[:40]]
    res["last_seen"] = max((a["date"] for a in res["articles"] if a["date"]), default="")

    # 文章 IOC 列表命中（by_ioc 只收文章里抽出的 IOC，不含正文顺带提到的词）
    res["article_ioc_hit"] = kind != "keyword" and bool(res["articles"])
    if res["records"] or res["article_ioc_hit"]:
        res["verdict"] = "malicious"
    elif res["parent_domains"] or res["related_urls"] or res["related_samples"]:
        res["verdict"] = "suspicious"
    else:
        res["verdict"] = "unknown"
    # 安全厂商 / 媒体 / CERT 站点：库里的记录多是文章引用链接被误收，不判恶意
    rh = norm if kind == "domain" else (res.get("host") if kind == "url" else "")
    if rh and is_report_host(rh):
        res["report_host"] = rh
        res["verdict_raw"] = res["verdict"]
        res["verdict"] = "unknown"
    return res


# ============================================================
# 路由
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")


# 库记录数 COUNT(*) 约 1s，状态接口轮询时用缓存，按 mtime 异步刷新
_db_meta = {"count": None, "mtime": 0, "size": 0, "counting": False}
_db_meta_lock = threading.Lock()


def _refresh_db_count(force=False):
    if not os.path.isfile(DB_PATH):
        with _db_meta_lock:
            _db_meta.update({"count": None, "mtime": 0, "size": 0})
        return
    mtime = os.path.getmtime(DB_PATH)
    size = os.path.getsize(DB_PATH)
    with _db_meta_lock:
        if not force and _db_meta["count"] is not None and _db_meta["mtime"] == mtime:
            return
        if _db_meta["counting"]:
            return
        _db_meta["counting"] = True
        _db_meta["mtime"] = mtime
        _db_meta["size"] = size

    def _job():
        cnt = None
        try:
            conn = db()
            try:
                cnt = conn.execute("SELECT COUNT(*) FROM ioc_records").fetchone()[0]
            finally:
                conn.close()
        except Exception:
            pass
        with _db_meta_lock:
            if cnt is not None:
                _db_meta["count"] = cnt
            _db_meta["counting"] = False

    threading.Thread(target=_job, daemon=True).start()


def _status_payload():
    load_intel()
    _refresh_db_count()
    arts = _intel["articles"]
    dark = _intel["darkweb"]
    now = datetime.now(timezone.utc)
    today0 = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    day3 = (now - timedelta(days=3)).timestamp()
    with _db_meta_lock:
        ioc_count = _db_meta["count"]
        db_mtime = _db_meta["mtime"] or (os.path.getmtime(DB_PATH) if os.path.isfile(DB_PATH) else 0)
        db_size = _db_meta["size"] or (os.path.getsize(DB_PATH) if os.path.isfile(DB_PATH) else 0)
    latest_art = max((a["_ts"] for a in arts if a.get("_ts")), default=0)
    latest_dark = max((d["_ts"] for d in dark if d.get("_ts")), default=0)
    sig = _intel.get("sig") or (0, 0)
    return {
        "ok": os.path.isfile(DB_PATH),
        "db_exists": os.path.isfile(DB_PATH),
        "db_mtime": int(db_mtime) if db_mtime else 0,
        "db_mtime_iso": datetime.fromtimestamp(db_mtime).strftime("%Y-%m-%d %H:%M") if db_mtime else "",
        "db_size_mb": round(db_size / (1024 * 1024), 1) if db_size else 0,
        "ioc_count": ioc_count,
        "article_count": len(arts),
        "darkweb_count": len(dark),
        "today_articles": sum(1 for a in arts if a.get("_ts", 0) >= today0),
        "recent_3d_articles": sum(1 for a in arts if a.get("_ts", 0) >= day3),
        "latest_article_ts": int(latest_art) if latest_art else 0,
        "latest_article_date": datetime.fromtimestamp(latest_art, tz=timezone.utc).strftime("%Y-%m-%d") if latest_art else "",
        "latest_darkweb_ts": int(latest_dark) if latest_dark else 0,
        "intel_sig": "{}:{}".format(sig[0], int(sig[1])),
        "server_time": int(time.time()),
    }


@app.route("/api/status")
def api_status():
    return jsonify(_status_payload())


@app.route("/api/hot_tags")
def api_hot_tags():
    """近期情报文章里出现最多的行为者 / 恶意家族（来自文章，不读库）。"""
    load_intel()
    limit = _int_arg("limit", 24, 1, 60)
    counts = {}
    recent = [a for a in _intel["articles"] if not set(a["cats"]) <= _HOT_TAG_SKIP][:400]
    for a in recent:
        seen = set()
        for kind, names in (("actor", a["actors"]), ("malware", a["malware"])):
            for n in names:
                k = n.lower()
                if k in seen or len(n) < 3:
                    continue
                seen.add(k)
                key = (kind, n)
                counts[key] = counts.get(key, 0) + 1
    top = sorted(counts.items(), key=lambda x: -x[1])[:limit]
    return jsonify([{"kind": k, "name": n, "count": c} for (k, n), c in top])


def _article_cutoff(days):
    """days=1 取今天 0 点起；3/7 取近 N 个 24h。"""
    now = datetime.now(timezone.utc)
    if days == 1:
        return now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    return (now - timedelta(days=days)).timestamp()


def _article_brief_public(a, since_ts=0):
    out = _article_brief(a)
    out["ts"] = int(a.get("_ts") or 0)
    if since_ts and out["ts"] >= since_ts:
        out["is_new"] = True
    return out


@app.route("/api/articles")
def api_articles():
    load_intel()
    _refresh_db_count()
    offset = _int_arg("offset", 0, 0, 1000000)
    limit = _int_arg("limit", 20, 1, 100)
    only_ioc = request.args.get("with_ioc") == "1"
    source = (request.args.get("source") or "").strip()[:100]
    kw = (request.args.get("q") or "").strip().lower()[:100]
    cat = (request.args.get("cat") or "").strip()
    topic = (request.args.get("topic") or "").strip()
    days = _int_arg("days", 0, 0, 90)
    since_ts = _int_arg("since", 0, 0, 4102444800)
    if _CONTROL_CHARS.search(source + kw):
        raise BadRequest("筛选条件包含非法字符")
    if cat and cat not in CATEGORIES:
        raise BadRequest("未知的情报类别")
    if topic and topic not in TOPICS:
        raise BadRequest("未知的专项主题")
    if days and days not in (1, 3, 7, 14, 30):
        raise BadRequest("days 仅支持 1 / 3 / 7 / 14 / 30")
    grp = etda_group(kw) if kw else None
    pool = [a for a in _intel["articles"] if kw in a["_blob"] or (grp and _article_matches_group(a, grp))] \
        if kw else _intel["articles"]
    if days:
        cutoff = _article_cutoff(days)
        pool = [a for a in pool if a.get("_ts", 0) >= cutoff]
    if topic:
        pool = [a for a in pool if topic in (a.get("topics") or [])]
    base = [a for a in pool if a["ioc_count"]] if only_ioc else pool
    cats, cats_all = {}, {}
    for a in pool:
        for c in a["cats"]:
            cats_all[c] = cats_all.get(c, 0) + 1
            if a["ioc_count"] or not only_ioc:
                cats[c] = cats.get(c, 0) + 1
    all_count = len(base)
    if cat:
        base = [a for a in base if cat in a["cats"]]
    sources = {}
    for a in base:
        if a["source"]:
            sources[a["source"]] = sources.get(a["source"], 0) + 1
    items = [a for a in base if a["source"] == source] if source else base
    new_total = sum(1 for a in items if since_ts and a.get("_ts", 0) >= since_ts) if since_ts else 0
    # 专项计数：不受当前 topic 过滤影响，便于导航展示总量
    topic_counts = _intel.get("topic_counts") or {}
    with _db_meta_lock:
        db_ioc_count = _db_meta["count"]
    return jsonify({
        "total": len(items),
        "items": [_article_brief_public(a, since_ts) for a in items[offset:offset + limit]],
        "sources": [{"name": n, "count": c} for n, c in sorted(sources.items(), key=lambda x: -x[1])[:40]],
        "source_total": len(sources),
        # 当前筛选条件下，文章正文提取到的 IOC 合计（≠ 主库 ioc_data.db）
        "ioc_total": sum(a["ioc_count"] for a in items),
        "db_ioc_count": db_ioc_count,
        "categories": [{"key": k, "label": v, "count": cats.get(k, 0), "count_all": cats_all.get(k, 0)}
                       for k, v in CATEGORIES.items()],
        "topics": [{"key": k, "label": v, "count": topic_counts.get(k, 0)} for k, v in TOPICS.items()],
        "topic": topic or None,
        "all_count": all_count,
        "new_total": new_total,
        "days": days or None,
        "geo_ready": bool(_get_geo_reader()),
    })


@app.route("/api/article/<int:aid>")
def api_article(aid):
    load_intel()
    if aid < 0 or aid >= len(_intel["articles"]):
        return jsonify({"error": "not found"}), 404
    a = _intel["articles"][aid]
    return jsonify({k: v for k, v in a.items() if k not in ("_ts", "_blob")})


@app.route("/api/topics")
def api_topics():
    """首页专项计数（不受文章列表筛选影响）。"""
    load_intel()
    counts = _intel.get("topic_counts") or {}
    return jsonify({
        "topics": [{"key": k, "label": v, "count": counts.get(k, 0)} for k, v in TOPICS.items()],
        "darkweb_count": len(_intel.get("darkweb") or []),
        "user_ioc_count": len(load_user_iocs()),
    })


def load_user_iocs():
    """用户手动提交的 IOC（与主库分离，不写 ioc_data.db）。"""
    try:
        with open(USER_INTEL_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []
    except (OSError, ValueError, TypeError):
        return []


def save_user_iocs(items):
    os.makedirs(INTEL_DIR, exist_ok=True)
    tmp = USER_INTEL_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(items, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, USER_INTEL_PATH)


def _parse_submit_lines(text, malware="", note="", source=""):
    """把多行文本拆成 IOC 记录。"""
    out, seen = [], set()
    malware = (malware or "").strip()[:80]
    note = (note or "").strip()[:200]
    source = (source or "").strip()[:80] or "用户提交"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for line in re.split(r"[\r\n]+", text or ""):
        raw = line.strip().strip(",;|")
        if not raw or raw.startswith("#"):
            continue
        for part in re.split(r"[\s,;|]+", raw):
            part = part.strip().strip(",;|")
            if len(part) < 3:
                continue
            kind, norm = detect(part)
            if kind == "keyword":
                continue
            typ = "file_hash" if kind == "file_hash" else kind
            key = (typ, norm.lower())
            if key in seen:
                continue
            seen.add(key)
            ip_only = ""
            if kind == "ip":
                m = _IPV4.match(norm)
                ip_only = m.group(1) if m else norm.split(":")[0]
            elif kind == "url":
                try:
                    ip_only = (urlparse(norm).hostname or "")
                except ValueError:
                    ip_only = ""
            out.append({
                "type": typ, "value": norm, "ip_only": ip_only,
                "source": source, "malware": malware, "note": note,
                "date": now, "families": split_names(malware) if malware else [],
            })
            if len(out) >= 200:
                return out
    return out


def match_user_iocs(kind, norm):
    """在用户提交库里匹配查询值。"""
    items = load_user_iocs()
    if not items:
        return []
    hits = []
    low = (norm or "").lower()
    for r in items:
        t, v = r.get("type"), (r.get("value") or "")
        vl = v.lower()
        ok = False
        if kind == "ip":
            ip = _IPV4.match(norm)
            ip = ip.group(1) if ip else norm.split(":")[0]
            ok = (r.get("ip_only") == ip) or vl == low or vl.startswith(ip + ":")
        elif kind == "file_hash":
            ok = t == "file_hash" and vl == low
        elif kind == "domain":
            ok = t == "domain" and (vl == low or vl.endswith("." + low))
        elif kind == "url":
            ok = t == "url" and vl == low
        elif kind == "keyword":
            ok = low in vl or low in (r.get("malware") or "").lower() or low in (r.get("note") or "").lower()
        if ok:
            hits.append({
                "type": t, "value": v, "ip_only": r.get("ip_only") or "",
                "source": r.get("source") or "用户提交",
                "malware": r.get("malware") or "",
                "families": r.get("families") or split_names(r.get("malware")),
            })
        if len(hits) >= 100:
            break
    return hits


@app.route("/api/user_intel", methods=["GET", "POST"])
def api_user_intel():
    if request.method == "GET":
        items = load_user_iocs()
        return jsonify({"total": len(items), "items": list(reversed(items[-80:]))})
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or data.get("iocs") or "").strip()
    if not text:
        raise BadRequest("请粘贴至少一条 IP / 域名 / URL / 哈希")
    if len(text) > 100000:
        raise BadRequest("内容过长")
    if _CONTROL_CHARS.search(text.replace("\n", "").replace("\r", "").replace("\t", "")):
        raise BadRequest("内容包含非法控制字符")
    rows = _parse_submit_lines(
        text,
        malware=(data.get("malware") or "")[:80],
        note=(data.get("note") or "")[:200],
        source=(data.get("source") or "")[:80],
    )
    if not rows:
        raise BadRequest("未识别到有效 IOC（请每行一条，支持 IP / 域名 / URL / 哈希）")
    with _user_intel_lock:
        existing = load_user_iocs()
        seen = {(r.get("type"), (r.get("value") or "").lower()) for r in existing}
        added = 0
        for r in rows:
            key = (r["type"], r["value"].lower())
            if key in seen:
                continue
            existing.append(r)
            seen.add(key)
            added += 1
        if len(existing) > 20000:
            existing = existing[-20000:]
        save_user_iocs(existing)
    return jsonify({"ok": True, "added": added, "skipped": len(rows) - added, "total": len(existing)})


def _dark_brief(d):
    return {k: v for k, v in d.items() if k != "_ts"}


@app.route("/api/darkweb")
def api_darkweb():
    load_intel()
    limit = _int_arg("limit", 10, 1, 500)
    offset = _int_arg("offset", 0, 0, 100000)
    group = (request.args.get("group") or "").strip().lower()[:80]
    country = (request.args.get("country") or "").strip().lower()[:8]
    sector = (request.args.get("sector") or "").strip().lower()[:60]
    if _CONTROL_CHARS.search(group + country + sector):
        raise BadRequest("筛选条件包含非法字符")
    items = _intel["darkweb"]
    if group:
        items = [d for d in items if d["group"].lower() == group]
    if country:
        items = [d for d in items if d["country"].lower() == country]
    if sector:
        items = [d for d in items if d["sector"].lower() == sector]
    groups, countries, sectors = {}, {}, {}
    for d in _intel["darkweb"]:
        for key, bucket in ((d["group"], groups), (d["country"], countries), (d["sector"], sectors)):
            if key:
                bucket[key] = bucket.get(key, 0) + 1
    top = lambda b, n: [{"name": k, "count": c} for k, c in sorted(b.items(), key=lambda x: -x[1])[:n]]
    return jsonify({
        "total": len(items),
        "items": [_dark_brief(d) for d in items[offset:offset + limit]],
        "groups": top(groups, 20),
        "countries": top(countries, 15),
        "sectors": top(sectors, 12),
    })


@app.route("/api/darkweb/<int:did>")
def api_darkweb_item(did):
    """单条暗网勒索事件：同团伙近期受害者 + 安全博客里提到该团伙的文章（均不读库）。"""
    load_intel()
    if did < 0 or did >= len(_intel["darkweb"]):
        return jsonify({"error": "not found"}), 404
    d = _intel["darkweb"][did]
    g = d["group"].lower()
    same = [x for x in _intel["darkweb"] if g and x["group"].lower() == g]
    countries, sectors = {}, {}
    for x in same:
        if x["country"]:
            countries[x["country"]] = countries.get(x["country"], 0) + 1
        if x["sector"]:
            sectors[x["sector"]] = sectors.get(x["sector"], 0) + 1
    arts = []
    if len(g) >= 3:
        # 团伙名常和别的名字撞（helix vs Helix Kitten），标题命中时要求同时出现勒索语境词
        pat = re.compile(r"(?<![a-z0-9]){}(?![a-z0-9])(?!\s+(kitten|panda|bear|spider|typhoon|tempest|sleet|blizzard))".format(re.escape(g)))
        ctx = re.compile(r"ransom|leak|extort|victim|data breach|勒索")
        title_hit, tag_hit = [], []
        for a in _intel["articles"]:
            t = a["title"].lower()
            if pat.search(t) and (ctx.search(t) or any(g == str(x).lower() for x in a["actors"] + a["malware"])):
                title_hit.append(dict(_article_brief(a), mention="title"))
            elif any(g == str(x).lower() for x in a["actors"] + a["malware"]):
                tag_hit.append(dict(_article_brief(a), mention="body"))
        arts = (title_hit + tag_hit)[:20]
    return jsonify({
        "item": _dark_brief(d),
        "group_total": len(same),
        "first_seen": min((x["date"] for x in same if x["date"]), default=""),
        "last_seen": max((x["date"] for x in same if x["date"]), default=""),
        "victims": [_dark_brief(x) for x in same if x["id"] != did][:50],
        "group_profile": _intel.get("rl_groups", {}).get(g) or {},
        "coverage_from": min((x["date"] for x in _intel["darkweb"] if x["date"]), default=""),
        "coverage_to": max((x["date"] for x in _intel["darkweb"] if x["date"]), default=""),
        "top_countries": sorted(countries.items(), key=lambda x: -x[1])[:8],
        "top_sectors": sorted(sectors.items(), key=lambda x: -x[1])[:8],
        "articles": arts,
    })


_kw_hits = defaultdict(deque)
_kw_lock = threading.Lock()
_kw_slots = threading.BoundedSemaphore(KEYWORD_CONCURRENCY)


def _keyword_allowed(ip):
    """关键词检索要整表扫描，按来源 IP 限速，避免被刷成 DoS。"""
    now = time.time()
    with _kw_lock:
        q = _kw_hits[ip]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= KEYWORD_PER_MINUTE:
            return False
        q.append(now)
        return True


@app.route("/api/related_samples")
def api_related_samples():
    """按家族异步拉取关联样本（与主查询分离，避免拖垮 IP / 域名研判）。"""
    if not os.path.isfile(DB_PATH):
        return jsonify({"error": "找不到情报库 ioc_data.db"}), 500
    raw = (request.args.get("families") or "").strip()
    if not raw or _CONTROL_CHARS.search(raw):
        raise BadRequest("families 无效")
    fams = [x.strip() for x in raw.split(",") if x.strip()][:5]
    if not fams or any(len(f) > MAX_TAG_LEN for f in fams):
        raise BadRequest("families 无效")
    exclude = [x.strip().lower() for x in (request.args.get("exclude") or "").split(",") if x.strip()][:80]
    conn = db(timeout_s=18)
    try:
        items = _related_samples(conn, fams, exclude)
    except sqlite3.OperationalError:
        items = []
    finally:
        conn.close()
    return jsonify({"items": items, "total": len(items)})


# ============================================================
# 批量查询 / 文本提取 IOC
# ============================================================
BATCH_MAX = 500
_batch_hits = deque()


def _rate_ok(bucket, per_minute):
    now = time.time()
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= per_minute:
        return False
    bucket.append(now)
    return True


def _public_ipv4(ip):
    try:
        import ipaddress
        return ipaddress.IPv4Address(ip).is_global
    except ValueError:
        return False


def extract_for_batch(text):
    """从清单或整段文本（报告 / 告警 / 邮件）里提取 IOC。
    每行最多一个词的视为 IOC 清单，按原样识别；否则按正文处理，域名走 TLD 白名单防止 setup.exe 之类误报。"""
    t = refang_text(text or "")
    lines = [ln.strip() for ln in t.splitlines() if ln.strip()]
    list_mode = bool(lines) and sum(1 for ln in lines if len(ln.split()) <= 1) >= 0.8 * len(lines)
    out, seen, skipped = [], set(), {"private_ip": 0, "invalid": 0}

    def add(kind, norm):
        key = (kind, norm.lower())
        if key in seen or len(out) >= BATCH_MAX:
            return
        if kind == "ip":
            ip = _IPV4.match(norm).group(1)
            if any(int(p) > 255 for p in ip.split(".")):
                skipped["invalid"] += 1
                return
            if not _public_ipv4(ip):
                skipped["private_ip"] += 1
                return
        if kind == "domain" and not list_mode and not is_valid_domain(norm):
            return
        seen.add(key)
        out.append((kind, norm))

    for tok in re.split(r"[\s,;|\"'<>()\[\]{}]+", t):
        tok = tok.strip().rstrip(".:")
        if len(tok) < 4:
            continue
        kind, norm = detect(tok)
        if kind != "keyword":
            add(kind, norm)
    if not list_mode:
        for typ, vals in extract_iocs(t).items():
            for v in vals:
                kind, norm = detect(v)
                if kind != "keyword":
                    add(kind, norm)
    return out, skipped, list_mode


def quick_check(conn, kind, norm):
    """批量用的单条研判：只查精确命中 + 父域名 / 主机，不拉关联 URL 与样本。"""
    rec, par, host, ip = [], [], "", ""
    if kind == "ip":
        ip = _IPV4.match(norm).group(1)
        rec = _rows(conn.execute(COLS + "WHERE ip_only = ? LIMIT 60", (ip,)))
        rec += _rows(conn.execute(COLS + "WHERE type = 'ip' AND value = ?", (norm,)))
        values = [ip, norm]
    elif kind == "file_hash":
        rec = _rows(conn.execute(COLS + "WHERE type = 'file_hash' AND value = ?", (norm,)))
        values = [norm]
    elif kind == "domain":
        rec = _rows(conn.execute(COLS + "WHERE type = 'domain' AND value = ?", (norm,)))
        labels = norm.split(".")
        for p in [".".join(labels[i:]) for i in range(1, len(labels) - 1)]:
            par += _rows(conn.execute(COLS + "WHERE type = 'domain' AND value = ?", (p,)))
        values = [norm]
    else:
        rec = _rows(conn.execute(COLS + "WHERE type = 'url' AND value = ?", (norm,)))
        host = (urlparse(norm).hostname or "").lower()
        if host and _IPV4.match(host):
            ip = host
            par = _rows(conn.execute(COLS + "WHERE ip_only = ? LIMIT 30", (host,)))
        elif host:
            par = _rows(conn.execute(COLS + "WHERE type = 'domain' AND value = ?", (host,)))
        values = [norm, host]
    profile = [r for r in rec + par if r["type"] == "ip_profile"]
    rec = _dedupe([r for r in rec if r["type"] != "ip_profile"] + match_user_iocs(kind, norm))
    par = _dedupe([r for r in par if r["type"] != "ip_profile"])
    arts = articles_for([v for v in values if v])
    fam, src = Counter(), Counter()
    for r in rec + par:
        for n in split_names(r.get("malware")):
            fam[n] += 1
        s = normalize_source(r.get("source"))
        if s and len(s) <= MAX_TAG_LEN:
            src[s] += 1
    for a in arts[:10]:
        for n in (a.get("malware") or []) + (a.get("actors") or []):
            fam[n] += 0
    if rec or arts:
        verdict = "malicious"
    elif par:
        verdict = "suspicious"
    else:
        verdict = "unknown"
    rh = norm if kind == "domain" else (host if kind == "url" else "")
    report_host = bool(rh) and is_report_host(rh)
    if report_host:
        verdict = "unknown"
    enrich = None
    if ip:
        try:
            from ip_enrich import lookup as ip_enrich_lookup
            enrich = ip_enrich_lookup(ip).get("summary") or ""
        except Exception:
            enrich = ""
    if enrich is None and profile:
        enrich = "/".join(sorted({(r.get("source") or "").replace("IP画像·", "") for r in profile}))
    return {
        "value": norm, "kind": kind, "verdict": verdict,
        "records": len(rec), "parents": len(par), "articles": len(arts),
        "article": ({"id": arts[0]["id"], "title": arts[0]["title"], "date": arts[0]["date"]} if arts else None),
        "families": [n for n, _ in fam.most_common(5)],
        "sources": [n for n, _ in src.most_common(3)],
        "profile": ("安全厂商 / 媒体站点（文章引用）" if report_host else (enrich or "")),
    }


@app.route("/api/batch", methods=["POST"])
def api_batch():
    if not os.path.isfile(DB_PATH):
        return jsonify({"error": "找不到情报库 ioc_data.db"}), 500
    if not _rate_ok(_batch_hits, 10):
        return jsonify({"error": "批量查询过于频繁，请稍后再试"}), 429
    data = request.get_json(silent=True) or {}
    text = data.get("text") or ""
    if not text.strip():
        raise BadRequest("请粘贴 IOC 清单或包含 IOC 的文本")
    if len(text) > 300000:
        raise BadRequest("内容过长（最多 30 万字符）")
    load_intel()
    t0 = time.time()
    items, skipped, list_mode = extract_for_batch(text)
    if not items:
        return jsonify({"items": [], "summary": {}, "skipped": skipped, "list_mode": list_mode,
                        "error": "没有识别到 IP / 域名 / URL / 哈希"})
    conn = db(timeout_s=60)
    out = []
    try:
        for kind, norm in items:
            try:
                out.append(quick_check(conn, kind, norm))
            except sqlite3.OperationalError:
                out.append({"value": norm, "kind": kind, "verdict": "error", "records": 0, "parents": 0,
                            "articles": 0, "families": [], "sources": [], "profile": ""})
    finally:
        conn.close()
    summary = Counter(r["verdict"] for r in out)
    return jsonify({
        "items": out, "summary": dict(summary), "total": len(out), "truncated": len(items) >= BATCH_MAX,
        "skipped": skipped, "list_mode": list_mode, "elapsed_ms": int((time.time() - t0) * 1000),
    })


# ============================================================
# 域名解析联动（按需触发：会向本机 DNS 发起真实查询）
# ============================================================
_resolve_hits = deque()


def _resolve_a(domain, timeout=4.0):
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout
    ex = ThreadPoolExecutor(max_workers=1)
    try:
        fut = ex.submit(socket.getaddrinfo, domain, None, socket.AF_INET, socket.SOCK_STREAM)
        infos = fut.result(timeout=timeout)
    except FutTimeout:
        raise RuntimeError("DNS 解析超时")
    except socket.gaierror:
        return []
    finally:
        ex.shutdown(wait=False)
    return list(dict.fromkeys(i[4][0] for i in infos))[:16]


@app.route("/api/resolve")
def api_resolve():
    d = (request.args.get("domain") or "").strip().lower().rstrip(".")
    if not _DOMAIN.match(d):
        raise BadRequest("domain 无效")
    if not _rate_ok(_resolve_hits, 20):
        return jsonify({"error": "解析过于频繁，请稍后再试"}), 429
    try:
        ips = _resolve_a(d)
    except RuntimeError as e:
        return jsonify({"domain": d, "ips": [], "error": str(e)})
    load_intel()
    out = []
    note = ""
    if ips and all(ip.startswith(("198.18.", "198.19.")) for ip in ips):
        note = "解析结果是 198.18.0.0/15 的 Fake-IP，说明本机代理（如 Clash TUN）接管了 DNS，拿到的不是真实地址；需在代理里放行面板主机的 DNS 或改用直连后再解析"
    conn = db()
    try:
        for ip in ips:
            if not _public_ipv4(ip):
                out.append({"ip": ip, "verdict": "unknown", "private": True, "records": 0, "articles": 0,
                            "families": [], "sources": [], "profile": "内网 / 保留地址"})
                continue
            out.append(dict(quick_check(conn, "ip", ip), ip=ip))
    finally:
        conn.close()
    return jsonify({"domain": d, "ips": out, "note": note,
                    "resolved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})


# ============================================================
# 关注列表：run_all 之后提示新命中
# ============================================================
WATCH_PATH = os.path.join(INTEL_DIR, "watchlist.json")
_watch_lock = threading.Lock()
_new_ioc_cache = {}


def load_watch():
    try:
        with open(WATCH_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save_watch(items):
    os.makedirs(INTEL_DIR, exist_ok=True)
    tmp = WATCH_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(items, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, WATCH_PATH)


def _new_ioc_files(since_ts):
    """run_all 产出的 output/new_iocs_<本地时间>.csv，只取 since 之后的。"""
    import csv
    out = []
    for path in glob.glob(os.path.join(OUTPUT_DIR, "new_iocs_*.csv")):
        m = re.search(r"new_iocs_(\d{8})_(\d{6})\.csv$", path)
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").timestamp()
        except ValueError:
            continue
        if ts <= since_ts:
            continue
        mtime = os.path.getmtime(path)
        cached = _new_ioc_cache.get(path)
        if not cached or cached[0] != mtime:
            rows = []
            try:
                with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
                    for r in csv.DictReader(fh):
                        r["_akeys"] = {_alias_key(n) for n in split_names(r.get("malware"))}
                        r["_ts"] = ts
                        rows.append(r)
            except OSError:
                continue
            cached = _new_ioc_cache[path] = (mtime, rows)
        out.append(cached[1])
    return out


def _watch_keys(item):
    if item["kind"] != "keyword":
        return set()
    grp = etda_group(item["value"])
    keys = set(grp["keys"]) if grp else set()
    keys.add(_alias_key(item["value"]))
    return keys


def _watch_row_match(item, keys, r):
    kind, v = item["kind"], item["value"].lower()
    val = (r.get("value") or "").lower()
    typ = r.get("type")
    if kind == "keyword":
        return bool(keys & r["_akeys"])
    if kind == "ip":
        ip = v.split(":")[0]
        if (r.get("ip_only") or "") == ip or val == v or val.startswith(ip + ":"):
            return True
        return typ == "url" and (urlparse(val).hostname or "") == ip
    if kind == "domain":
        if typ == "domain":
            return val == v or val.endswith("." + v)
        if typ == "url":
            h = urlparse(val).hostname or ""
            return h == v or h.endswith("." + v)
        return False
    return val == v


def _watch_articles(item, keys, since_ts):
    arts = _intel["articles"]
    if item["kind"] == "keyword":
        idxs = set()
        for k in keys:
            idxs |= _intel["by_alias"].get(k, set())
        grp = etda_group(item["value"])
        hits = [arts[i] for i in idxs if arts[i].get("_ts", 0) > since_ts]
        if grp:
            seen = {a["id"] for a in hits}
            hits += [a for a in arts if a.get("_ts", 0) > since_ts and a["id"] not in seen
                     and _article_matches_group(a, grp)]
        return hits
    v = item["value"].lower()
    vals = [v]
    if item["kind"] == "ip":
        vals.append(v.split(":")[0])
    idxs = {i for x in vals for i in _intel["by_ioc"].get(x, [])}
    return [arts[i] for i in idxs if arts[i].get("_ts", 0) > since_ts]


def _watch_status(item):
    since = float(item.get("ack_ts") or item.get("added_ts") or 0)
    keys = _watch_keys(item)
    iocs = []
    for rows in _new_ioc_files(since):
        for r in rows:
            if _watch_row_match(item, keys, r):
                iocs.append({k: r.get(k, "") for k in ("type", "value", "ip_only", "source", "malware")})
    arts = sorted(_watch_articles(item, keys, since), key=lambda a: a.get("_ts", 0), reverse=True)
    return dict(item, new_ioc_count=len(iocs), new_iocs=iocs[:30],
                new_article_count=len(arts), new_articles=[_article_brief(a) for a in arts[:10]],
                new_total=len(iocs) + len(arts))


def _watch_find(value):
    kind, norm = detect(value)
    for it in load_watch():
        if it["kind"] == kind and it["value"].lower() == norm.lower():
            return it
    return None


@app.route("/api/watch", methods=["GET", "POST"])
def api_watch():
    load_intel()
    if request.method == "GET":
        items = [_watch_status(it) for it in load_watch()]
        items.sort(key=lambda x: (-x["new_total"], -float(x.get("added_ts") or 0)))
        return jsonify({"items": items, "total": len(items), "total_new": sum(1 for x in items if x["new_total"])})
    data = request.get_json(silent=True) or {}
    value = (data.get("value") or "").strip()
    if not value or len(value) > MAX_QUERY_LEN or _CONTROL_CHARS.search(value):
        raise BadRequest("关注内容无效")
    kind, norm = detect(value)
    if kind == "keyword" and len(norm) < 3:
        raise BadRequest("关键词至少 3 个字符")
    with _watch_lock:
        items = load_watch()
        for it in items:
            if it["kind"] == kind and it["value"].lower() == norm.lower():
                return jsonify({"ok": True, "item": it, "exists": True})
        if len(items) >= 500:
            raise BadRequest("关注列表已满（最多 500 条）")
        grp = etda_group(norm) if kind == "keyword" else None
        now = time.time()
        it = {"id": "%x%04x" % (int(now * 1000), len(items)), "value": norm, "kind": kind,
              "label": grp["name"] if grp else "", "note": (data.get("note") or "")[:200],
              "added_ts": now, "ack_ts": now}
        items.append(it)
        save_watch(items)
    return jsonify({"ok": True, "item": it})


@app.route("/api/watch/<wid>", methods=["DELETE"])
def api_watch_delete(wid):
    with _watch_lock:
        items = load_watch()
        left = [x for x in items if x.get("id") != wid]
        if len(left) == len(items):
            return jsonify({"error": "关注项不存在"}), 404
        save_watch(left)
    return jsonify({"ok": True})


@app.route("/api/watch/<wid>/ack", methods=["POST"])
def api_watch_ack(wid):
    with _watch_lock:
        items = load_watch()
        now = time.time()
        hit = False
        for x in items:
            if wid == "all" or x.get("id") == wid:
                x["ack_ts"] = now
                hit = True
        if not hit:
            return jsonify({"error": "关注项不存在"}), 404
        save_watch(items)
    return jsonify({"ok": True})


@app.route("/api/pipeline_summary")
def api_pipeline_summary():
    """首页「本轮采集」：读 run_all 产出的最新 new_iocs_<时间>.csv（不查主库）。"""
    import csv
    runs = []
    for p in glob.glob(os.path.join(OUTPUT_DIR, "new_iocs_*.csv")):
        m = re.search(r"new_iocs_(\d{8})_(\d{6})\.csv$", p)
        if m:
            try:
                runs.append((datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S"), p))
            except ValueError:
                pass
    runs.sort()
    files = [p for _, p in runs]
    out = {"last_run": "", "new_total": 0, "by_type": {}, "by_source": [], "runs_7d": 0}
    if files:
        path = files[-1]
        out["last_run"] = runs[-1][0].strftime("%Y-%m-%d %H:%M")
        mtime = os.path.getmtime(path)
        cached = _new_ioc_cache.get("summary:" + path)
        if not cached or cached[0] != mtime:
            types, srcs, n = Counter(), Counter(), 0
            try:
                with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
                    for r in csv.DictReader(fh):
                        n += 1
                        types[r.get("type") or "?"] += 1
                        s = normalize_source(r.get("source"))
                        if s:
                            srcs[s] += 1
            except OSError:
                pass
            cached = _new_ioc_cache["summary:" + path] = (mtime, n, dict(types), srcs.most_common(5))
        out.update({"new_total": cached[1], "by_type": cached[2], "by_source": cached[3]})
        week = time.time() - 7 * 86400
        out["runs_7d"] = sum(1 for f in files if os.path.getmtime(f) >= week)
    return jsonify(out)


# ============================================================
# APT 组织 / 恶意家族专题
# ============================================================
_apt_cache = {"sig": None, "rows": []}


def _group_article_ids(g):
    ids = set()
    for k in g["keys"]:
        ids |= _intel["by_alias"].get(k, set())
    return ids


def _apt_rows():
    e = load_etda()
    info = fidx.index_info()
    sig = (_intel.get("sig"), e["mtime"], info.get("mtime"))
    if _apt_cache["sig"] == sig:
        return _apt_cache["rows"]
    totals = fidx.akey_totals()
    arts = _intel["articles"]
    rows = []
    for g in e["groups"]:
        ids = _group_article_ids(g)
        last = max((arts[i]["date"] for i in ids if arts[i].get("date")), default="")
        rows.append({
            "name": g["name"], "names": g["names"][:12], "alias_count": len(g["names"]),
            "country": g["country"], "motivation": g["motivation"], "state": g["state"],
            "first_seen": g["first_seen"], "articles": len(ids), "last_article": last,
            "iocs": sum(totals.get(k, 0) for k in g["keys"]),
        })
    _apt_cache.update({"sig": sig, "rows": rows})
    return rows


@app.route("/api/apt_groups")
def api_apt_groups():
    load_intel()
    q = (request.args.get("q") or "").strip().lower()[:60]
    country = (request.args.get("country") or "").strip()[:40]
    scope = request.args.get("scope") or "apt"
    sort = request.args.get("sort") or "articles"
    offset = _int_arg("offset", 0, 0, 100000)
    limit = _int_arg("limit", 30, 1, 100)
    rows = _apt_rows()
    countries = Counter(c for r in rows if (scope == "all" or r["state"]) for c in r["country"])
    pool = [r for r in rows if scope == "all" or r["state"]]
    if country:
        pool = [r for r in pool if country in r["country"]]
    if q:
        qk = _alias_key(q)
        pool = [r for r in pool if any(qk in _alias_key(n) for n in r["names"]) or qk in _alias_key(r["name"])]
    if sort == "recent":
        pool = sorted(pool, key=lambda r: r["last_article"], reverse=True)
    elif sort == "iocs":
        pool = sorted(pool, key=lambda r: (-r["iocs"], -r["articles"]))
    elif sort == "name":
        pool = sorted(pool, key=lambda r: r["name"].lower())
    else:
        pool = sorted(pool, key=lambda r: (-r["articles"], -r["iocs"]))
    return jsonify({"total": len(pool), "items": pool[offset:offset + limit],
                    "countries": countries.most_common(30), "index": fidx.index_info()})


@app.route("/api/families")
def api_families():
    q = (request.args.get("q") or "").strip()[:60]
    offset = _int_arg("offset", 0, 0, 1000000)
    limit = _int_arg("limit", 30, 1, 100)
    items, total = fidx.top_families(q, limit=limit, offset=offset)
    if items is None:
        return jsonify({"items": [], "total": 0, "index": {"ready": False}})
    load_intel()
    e = load_etda()
    for f in items:
        f["articles"] = len(_intel["by_alias"].get(f["akey"], ()))
        f["apt"] = e["groups"][e["by_key"][f["akey"]]]["name"] if f["akey"] in e["by_key"] else ""
    return jsonify({"items": items, "total": total, "index": fidx.index_info()})


@app.route("/api/profile")
def api_profile():
    """APT 组织或恶意家族专题：档案、IOC 统计与样例、相关文章、按月趋势。"""
    name = (request.args.get("name") or "").strip()
    if not name or len(name) > 80 or _CONTROL_CHARS.search(name):
        raise BadRequest("name 无效")
    load_intel()
    grp = etda_group(name)
    akeys = (set(grp["keys"]) if grp else set()) | {_alias_key(name)}
    fams = fidx.families_by_akeys(akeys)
    counts = Counter()
    sources = Counter()
    for f in fams:
        counts["total"] += f["total"]
        for t, n in f["counts"].items():
            counts[t] += n
        sources.update(f["sources"])
    arts = _intel["articles"]
    ids = set()
    for k in akeys:
        ids |= _intel["by_alias"].get(k, set())
    if grp:
        ids |= {a["id"] for a in arts if _article_matches_group(a, grp)}
    elif len(_alias_key(name)) >= 4:
        pat = re.compile(r"(?<![a-z0-9])" + re.escape(name.lower()) + r"(?![a-z0-9])")
        ids |= {a["id"] for a in arts if pat.search(a["title"].lower())}
    hit = sorted((arts[i] for i in ids), key=lambda a: a.get("_ts", 0), reverse=True)
    months = Counter((a.get("date") or "")[:7] for a in hit if a.get("date"))
    now = datetime.now()
    trend = []
    for i in range(11, -1, -1):
        y, m = now.year, now.month - i
        while m <= 0:
            y, m = y - 1, m + 12
        key = "%04d-%02d" % (y, m)
        trend.append({"month": key, "count": months.get(key, 0)})
    samples = []
    if fams and os.path.isfile(DB_PATH):
        conn = db()
        try:
            for t in ("ip", "domain", "url", "file_hash"):
                rows = _rows_by_rowid(conn, fidx.rowids_for([f["key"] for f in fams[:30]], types=[t], limit=60))
                for r in rows:
                    r["families"] = split_names(r.get("malware"))
                samples += rows
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
    related = Counter()
    for a in hit[:300]:
        for n in (a.get("malware") or []) + (a.get("actors") or []):
            if _alias_key(n) not in akeys:
                related[n] += 1
    return jsonify({
        "name": grp["name"] if grp else name, "query": name,
        "actor_profile": _etda_public(grp) if grp else None,
        "families": [{k: f[k] for k in ("name", "total", "counts")} for f in fams[:30]],
        "counts": dict(counts), "sources": sources.most_common(10),
        "samples": samples, "articles": [_article_brief(a) for a in hit[:60]], "article_total": len(hit),
        "trend": trend, "related": related.most_common(20),
        "watch": _watch_find(name), "index": fidx.index_info(),
    })


_abuse_hits = deque()


@app.route("/api/abuseipdb")
def api_abuseipdb():
    """AbuseIPDB 实时信誉（异步加载；本地缓存 24h + 每日配额，未配置 Key 时返回 configured=false）。"""
    ip = (request.args.get("ip") or "").strip()
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
        raise BadRequest("ip 无效")
    now = time.time()
    while _abuse_hits and now - _abuse_hits[0] > 60:
        _abuse_hits.popleft()
    if len(_abuse_hits) >= 30:
        return jsonify({"configured": True, "error": "查询过于频繁，请稍后再试"}), 429
    _abuse_hits.append(now)
    from ip_enrich import abuseipdb_check
    return jsonify(abuseipdb_check(ip))


@app.route("/api/search")
def api_search():
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"error": "请输入要查询的 IP / 域名 / URL / 哈希 / 家族名"}), 400
    if len(q) > MAX_QUERY_LEN:
        return jsonify({"error": "查询内容过长（最多 {} 个字符）".format(MAX_QUERY_LEN)}), 400
    if _CONTROL_CHARS.search(q):
        return jsonify({"error": "查询内容包含非法字符"}), 400
    if not os.path.isfile(DB_PATH):
        return jsonify({"error": "找不到情报库 ioc_data.db"}), 500
    load_intel()
    t0 = time.time()
    kind, _ = detect(q)
    try:
        if kind == "keyword":
            if not _keyword_allowed(request.remote_addr or "?"):
                return jsonify({"error": "关键词检索过于频繁，请稍后再试"}), 429
            if not _kw_slots.acquire(timeout=5):
                return jsonify({"error": "检索繁忙，请稍后再试"}), 503
            try:
                res = search(q)
            finally:
                _kw_slots.release()
        else:
            res = search(q)
    except sqlite3.OperationalError as e:
        if "interrupted" in str(e).lower():
            return jsonify({"error": "查询超时，请输入更精确的内容"}), 504
        app.logger.warning("search failed: %s", e)
        return jsonify({"error": "查询失败"}), 500
    except sqlite3.DatabaseError as e:
        app.logger.warning("search failed: %s", e)
        return jsonify({"error": "查询失败"}), 500
    res["elapsed_ms"] = int((time.time() - t0) * 1000)
    w = _watch_find(q)
    res["watch_id"] = w["id"] if w else ""
    return jsonify(res)


@app.errorhandler(BadRequest)
def _bad_request(e):
    return jsonify({"error": str(e)}), 400


@app.errorhandler(404)
def _not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "接口不存在"}), 404
    return render_template("index.html"), 404


@app.errorhandler(405)
def _method_not_allowed(e):
    return jsonify({"error": "不支持的请求方法"}), 405


@app.errorhandler(500)
def _server_error(e):
    return jsonify({"error": "服务内部错误"}), 500


CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


@app.after_request
def _security_headers(resp):
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def _lan_ips():
    """探测本机局域网 IP，方便同事用 http://IP:端口 访问。"""
    found = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                found.append(ip)
        finally:
            s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127.") and ip not in found:
                found.append(ip)
    except OSError:
        pass
    return found


if __name__ == "__main__":
    # 默认 0.0.0.0：局域网可访问；仅本机请设 HUNTI_WEB_HOST=127.0.0.1
    host = os.environ.get("HUNTI_WEB_HOST", "0.0.0.0")
    port = int(os.environ.get("HUNTI_WEB_PORT", "5000"))
    print("=" * 60)
    print("威胁情报中心 Web 面板")
    print("=" * 60)
    print("情报库: {}".format(DB_PATH))
    print("文章目录: {}".format(INTEL_DIR))
    print("监听: {}:{}".format(host, port))
    print("本机: http://127.0.0.1:{}".format(port))
    if host in ("0.0.0.0", "::"):
        for ip in _lan_ips():
            print("局域网: http://{}:{}".format(ip, port))
        print("提示: 若同事打不开，检查 Windows 防火墙是否放行 TCP {}".format(port))
    else:
        print("访问: http://{}:{}".format(host, port))
    print("=" * 60)
    if not os.path.isfile(DB_PATH):
        print("[警告] 找不到 ioc_data.db，搜索将不可用")
    threading.Thread(target=load_intel, daemon=True).start()
    _refresh_db_count(force=True)
    app.run(host=host, port=port, debug=False, threaded=True)
