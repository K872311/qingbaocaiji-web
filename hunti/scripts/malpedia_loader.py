"""
malpedia.bib 集成模块
提供：URL 列表 + 关键词列表，供爬虫动态加载
"""
import json, os, re, time, subprocess
from collections import Counter

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

MALPEDIA_BIB_FILE = os.path.join(OUTPUT_DIR, "malpedia.bib")
MALPEDIA_URLS_FILE = os.path.join(OUTPUT_DIR, "malpedia_urls.txt")
MALPEDIA_KEYWORDS_FILE = os.path.join(OUTPUT_DIR, "malpedia_keywords.json")
MALPEDIA_REFRESH_DAYS = 14  # 每 14 天自动刷新一次


def refresh_malpedia(force: bool = False) -> bool:
    """
    自动检查并刷新 malpedia.bib
    如果文件不存在或超过 14 天未更新，自动重新下载并解析
    返回值: True=已刷新, False=无需刷新
    """
    need_download = force
    if os.path.exists(MALPEDIA_BIB_FILE):
        age_days = (time.time() - os.path.getmtime(MALPEDIA_BIB_FILE)) / 86400
        if age_days > MALPEDIA_REFRESH_DAYS:
            print(f"  malpedia.bib 已过期 ({age_days:.0f} 天)，重新下载...")
            need_download = True
    else:
        print("  malpedia.bib 不存在，下载中...")
        need_download = True

    if not need_download:
        return False

    # 下载
    import urllib.request
    url = "https://malpedia.caad.fkie.fraunhofer.de/api/get/bib"
    try:
        urllib.request.urlretrieve(url, MALPEDIA_BIB_FILE)
        size = os.path.getsize(MALPEDIA_BIB_FILE)
        print(f"  下载完成: {size//1024}KB")
    except Exception as e:
        print(f"  下载失败: {e}")
        return False

    # 解析
    parse_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parse_malpedia.py")
    try:
        r = subprocess.run(
            ["py", "-3", "-X", "utf8", parse_script, MALPEDIA_BIB_FILE],
            capture_output=True, text=True, timeout=180,
        )
        for line in r.stdout.strip().split("\n")[-10:]:
            print(f"    {line}")
    except Exception as e:
        print(f"  解析失败: {e}")
        return False

    return True


# 不是分析文章：社交、CVE 页、样本仓库、PDF 托管
_BAD_DOMAINS = {
    "twitter.com", "x.com", "youtube.com", "facebook.com",
    "linkedin.com", "github.com", "gitlab.com",
    "attack.mitre.org", "www.cve.org", "nvd.nist.gov",
    "bazaar.abuse.ch",
    "bsky.app",
    "www.virustotal.com",
    "virustotal.com",
}
_SKIP_URL_HINTS = (
    "hubspotusercontent",
    "/wp-content/uploads/",
    "/malware-trends/",
    "bazaar.abuse.ch/sample",
    "bazaar.abuse.ch/browse/",
)
_SKIP_SUFFIXES = (".pdf", ".zip", ".docx", ".pptx", ".xlsx", ".exe", ".gz")


def is_non_article_url(url: str) -> bool:
    """PDF/样本页/社交等，抓了也得不到可用 HTML。"""
    u = (url or "").strip().lower()
    if not u:
        return True
    path = u.split("?", 1)[0].split("#", 1)[0]
    if path.endswith(_SKIP_SUFFIXES):
        return True
    if any(h in u for h in _SKIP_URL_HINTS):
        return True
    m = re.search(r"https?://([^/]+)", u)
    if m:
        d = m.group(1)
        if any(bd in d for bd in _BAD_DOMAINS):
            return True
    return False


def load_malpedia_urls() -> list:
    """加载 malpedia 的 URL 列表，返回去重后的列表"""
    if not os.path.exists(MALPEDIA_URLS_FILE):
        return []
    with open(MALPEDIA_URLS_FILE, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]
    return [u for u in urls if not is_non_article_url(u)]


def load_malpedia_keywords(min_count: int = 3) -> list:
    """
    加载 malpedia 的关键词，过滤掉通用词/作者名
    返回恶意软件/APT 名称列表
    """
    if not os.path.exists(MALPEDIA_KEYWORDS_FILE):
        return []

    with open(MALPEDIA_KEYWORDS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 这些是作者名/通用词，不是恶意软件/APT
    NOISE_WORDS = {
        "team", "research", "labs", "group", "intelligence",
        "security", "center", "report", "response", "blog", "lab",
        "uk", "fbi", "cert", "tracker", "micro", "attack", "analysis",
        "saadi", "cimpanu", "krebs", "toulas", "gatlan", "ivanov",
        "ilascu", "lakshmanan", "singh", "chen", "zhang", "hahn",
        "duncan", "kremez", "slowik", "segura", "paganini",
        "cocomelonc", "abrams", "falcone", "tefanko", "hjelmvik",
        "reaves", "mhr", "prodaft", "threatfabric",
        "huntio", "asec", "certua", "cyfirma", "mandiant",
        "abusech", "anyrun", "push", "greenplan", "miyamoto",
        "antoniuk", "boychenko", "decker", "genians", "informer",
        "singha", "malhotra", "begoodtoall", "bykkaya", "cruz",
        "dexpose", "fielenbach", "lunghi", "moses", "pichon",
        "rochberger", "tru", "0x0d4y", "ctr", "cisa",
        "microsoft", "operations", "socket", "windows", "linux",
        "play", "inc", "http", "https",
        "bar", "ja3", "ja4", "jarm",
        "crowdstrike", "kaspersky", "rapid7", "talos", "virustotal",
        "cisco", "paloalto",
    }

    keywords = []
    for kw in data.get("keywords", []):
        name = kw["name"]
        count = kw["count"]
        # 过滤噪音
        if name not in NOISE_WORDS and len(name) > 2 and count >= min_count:
            keywords.append(name)

    return keywords
