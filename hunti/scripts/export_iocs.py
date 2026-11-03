"""
IOC 汇总导出工具 v2
从所有原始数据源直接读取，不做 merge 降质处理

读取:
  - output/iocs/rss_iocs_*.json       RSS 文章 IOC（高质量，来源名 + TA 完整）
  - output/iocs/url_iocs_*.json       URL 博客 IOC（同上）
  - output/iocs/tc_iocs_*.json        ThreatCluster IOC（公开 JSON + MISP）
  - output/iocs/tf_iocs_*.json        ThreatFox IOC（abuse.ch）
  - output/iocs/misp_iocs_*.json      MISP Default Feeds IOC
  - output/iocs/otx_iocs_*.json       OTX / LevelBlue 高质量 Pulse
  - output/iocs/thl_iocs_*.json       Hunter's Ledger 战役 JSON
  - output/history/apt/iocs_*.json    APT IOC（旧数据可能缺 TA，从 intel 补填）
  - output/history/apt/intelligence_*.json  用于 TA 回填
  - output/history/derp/all_iocs_*.json     derp.ca C2 / 研究 IOC

输出:
  - output/all_iocs_latest.json       简洁版（按类型分组）
  - output/all_iocs_detail_{ts}.json  明细版（每条带威胁信息）
"""
import json, glob, os, re
from datetime import datetime
from collections import defaultdict
from crawler_utils import (
    is_valid_ip,
    is_valid_hash,
    is_valid_domain as _shared_valid_domain,
    PLACEHOLDER_IPS,
    VALID_TLDS,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
IOC_DIR = os.path.join(OUTPUT_DIR, "iocs")
INTEL_DIR = os.path.join(OUTPUT_DIR, "intel")
HISTORY_DIR = os.path.join(OUTPUT_DIR, "history")
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")

KEEP_TYPES = {"ip", "domain", "md5", "sha1", "sha256", "url"}

# VALID_TLDS / PLACEHOLDER_IPS / is_valid_ip / is_valid_hash / is_valid_domain
# 均来自 crawler_utils，与采集端 rss_intel_monitor.py 共用同一套规则。

# ============================================================
# 排除的已知合法 / 误报域名
# ============================================================
EXCLUDE_DOMAIN_SUBSTRINGS = {
    "google.", "facebook.", "twitter.", "x.com", "youtube.",
    "instagram.", "reddit.", "linkedin.", "github.", "gitlab.",
    "bitbucket.", "npmjs.", "pypi.", "nuget.", "docker.",
    "amazon.", "apple.", "microsoft.", "wikipedia.",
    "torproject.", "abuse.ch", "duckdns.", "cloudflare.",
    "pastebin.", "telegram.", "steamcommunity.",
    "blogspot.", "medium.com", "wordpress.",
    "gmail.", "outlook.", "yahoo.", "protonmail.",
    "schema.org", "ietf.org", "w3.org", "mitre.org",
    "cisa.gov", "nist.gov", "whois.", "verisign.",
    "godaddy.", "namecheap.", "gname.",
    "sectigo.", "ssl.", "letsencrypt.",
    "realtimeregister.com",
    "www.group-ib.com", "www.welivesecurity.com",
    # 云存储/CDN 基础设施
    "windows.net", "amazonaws.com", "cloudfront.net",
    "googleapis.com", "googleusercontent.com", "appspot.com",
    "akamaihd.net", "akamaized.net", "fastly.net", "jsdelivr.net",
    "unpkg.com", "cdnjs.com", "bootstrapcdn.com",
    "sharepoint.com", "office.com", "mailchannels.net", "sendgrid.net",
}

EXACT_DOMAINS = {
    "gopkg.in", "mail.ru", "socket.io", "npmjs.org",
    "ycombinator.com", "news.ycombinator.com",
    "schema.org", "google.golang.org",
    "archive.org", "axios-http.com",
}

EXCLUDE_URL_SUBSTRINGS = (
    "localhost", "127.0.0.1", "0.0.0.0", "[::1]",
    "metadata.google.internal", "example.com", "example.org",
    "1.1.1.1", "8.8.8.8", "files.pythonhosted.org",
)

GENERIC_NOISE_TAGS = {
    "rat", "backdoor", "trojan", "loader", "dropper", "stealer",
    "infostealer", "worm", "botnet", "malware", "c2", "apt",
    "virus", "exploit", "payload", "ioc", "play",
    "microsoft", "operations", "socket", "windows", "linux",
    "macos", "android", "github", "google", "apple", "chrome",
    "python", "javascript", "nodejs", "http", "https", "inc",
}

EXCLUDE_DOMAIN_ENDINGS = (
    ".exe", ".dll", ".sys", ".so", ".dylib", ".wasm",
    ".bat", ".cmd", ".ps1", ".vbs", ".sh",
    ".py", ".js", ".ts", ".java", ".rs", ".go",
    ".md", ".txt", ".json", ".xml", ".csv", ".yaml", ".yml",
    ".cfg", ".conf", ".ini", ".log", ".toml",
    ".png", ".jpg", ".gif", ".svg", ".ico", ".webp",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".pdb", ".pdf", ".docx", ".xlsx",
    ".html", ".htm", ".php", ".asp", ".aspx", ".jsp",
)

# ============================================================
# 工具函数
# ============================================================

def load_json_files(pattern, dir_path):
    data = []
    for f in sorted(glob.glob(os.path.join(dir_path, pattern))):
        try:
            with open(f, "r", encoding="utf-8") as fp:
                d = json.load(fp)
                if isinstance(d, list):
                    data.extend(d)
                else:
                    data.append(d)
        except Exception:
            pass
    return data


def clean_defanged_value(value):
    v = re.sub(r'\\?\[\.\\?\]', '.', value)
    v = re.sub(r'\(\s*\.\s*\)', '.', v)
    v = re.sub(r'\{\s*\.\s*\}', '.', v)
    v = re.sub(r'\[\s*:\s*\]', ':', v)
    v = re.sub(r'\\(?=[.:/])', '', v)
    v = v.replace('hxxps://', 'https://').replace('hxxp://', 'http://')
    v = v.replace('[://]', '://')
    # 含占位符/不完整标签 → 无效
    if '<' in v or '>' in v or '...' in v or re.search(r'%[a-z]+%', v, re.I):
        return None
    return v


def is_valid_domain(domain):
    """在共用规则之上叠加本模块的白名单站点与文件后缀排除。"""
    d = (domain or "").lower().strip()
    if d.endswith(EXCLUDE_DOMAIN_ENDINGS):
        return False
    return _shared_valid_domain(
        d,
        exclude_substrings=tuple(EXCLUDE_DOMAIN_SUBSTRINGS),
        exclude_exact=EXACT_DOMAINS,
    )


# ============================================================
# 数据加载
# ============================================================

def load_rss_iocs():
    """加载 RSS/URL 路径的高质量 IOCs"""
    result = []
    seen_keys = set()

    for prefix, source_type in [
        ("rss_iocs_", "rss"),
        ("url_iocs_", "url"),
        ("tc_iocs_", "ThreatCluster"),
        ("tf_iocs_", "ThreatFox"),
        ("misp_iocs_", "MISP Feeds"),
        ("otx_iocs_", "OTX"),
        ("thl_iocs_", "Hunter's Ledger"),
    ]:
        items = load_json_files(f"{prefix}*.json", IOC_DIR)
        for item in items:
            ioc_type = item.get("ioc_type", "").lower()
            ioc_value = item.get("ioc_value", "").strip()
            if ioc_type not in KEEP_TYPES or not ioc_value:
                continue
            if prefix == "misp_iocs_" and ioc_type == "ip":
                continue

            key = f"{ioc_type}|{ioc_value}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            result.append({
                "type": ioc_type,
                "value": ioc_value,
                "source": item.get("source", source_type),
                "url": item.get("url", ""),
                "title": item.get("title", ""),
                "threat_actors": list(item.get("threat_actors", []) or []),
                "malware": list(item.get("malware", []) or []),
                "crawl_time": item.get("crawl_time", ""),
            })
    return result, seen_keys


def load_apt_iocs():
    """加载 APT 路径的 IOCs，从 intel 文章补填 TA"""
    result = []

    # 1. 加载 APT 历史 IOCs
    apt_iocs = load_json_files("iocs_*.json", os.path.join(HISTORY_DIR, "apt"))

    # 2. 加载 intel 文章（用于回填 TA）
    articles = []
    articles.extend(load_json_files("intelligence_*.json", os.path.join(HISTORY_DIR, "apt")))
    articles.extend(load_json_files("rss_intel_*.json", INTEL_DIR))
    articles.extend(load_json_files("url_intel_*.json", INTEL_DIR))

    # 按 URL 建立文章索引
    url_to_article = {}
    for art in articles:
        u = art.get("url", "")
        if u:
            url_to_article[u] = art

    for item in apt_iocs:
        source_url = item.get("source_url", "") or item.get("来源URL", "")
        ioc_type = (item.get("ioc_type", "") or item.get("IOC类型", "")).lower()
        ioc_value = (item.get("ioc_value", "") or item.get("IOC值", "")).strip()

        if ioc_type not in KEEP_TYPES or not ioc_value:
            continue

        # 已有 TA 则直接使用
        tas = list(item.get("threat_actors", []) or item.get("威胁行为者", []) or [])
        mw = list(item.get("malware", []) or item.get("恶意软件", []) or [])

        # 从来源文章补填
        if (not tas or not mw) and source_url in url_to_article:
            article = url_to_article[source_url]
            if not tas:
                tas = list(article.get("threat_actors", []) or [])
            if not mw:
                mw = list(article.get("malware", []) or [])

        # 从 URL 推断来源名
        source = _infer_source_from_url(source_url) if source_url else "APT"

        result.append({
            "type": ioc_type,
            "value": ioc_value,
            "source": source,
            "url": source_url,
            "title": url_to_article.get(source_url, {}).get("title", ""),
            "threat_actors": tas,
            "malware": mw,
            "crawl_time": item.get("crawl_time", ""),
        })

    return result


def _infer_source_from_url(url):
    """从 URL 推断来源名称（改进版，避免 Or/Co/Qq 类脏名）"""
    import re
    # 直接从源列表提取
    SOURCE_DOMAINS = {
        "thehackernews.com": "The Hacker News",
        "bleepingcomputer.com": "BleepingComputer",
        "krebsonsecurity.com": "Krebs on Security",
        "securityaffairs.com": "Security Affairs",
        "welivesecurity.com": "WeLiveSecurity",
        "securelist.com": "Securelist",
        "securelist.ru": "Securelist RU",
        "ics-cert.kaspersky.com": "Kaspersky ICS CERT",
        "threatcluster.io": "ThreatCluster",
        "derp.ca": "Derp",
        "threatfox.abuse.ch": "ThreatFox",
        "darkreading.com": "Dark Reading",
        "securityweek.com": "SecurityWeek",
        "cyberscoop.com": "CyberScoop",
        "therecord.media": "The Record",
        "infosecurity-magazine.com": "Infosecurity Mag",
        "scworld.com": "SC World",
        "csoonline.com": "CSO Online",
        "any.run": "AnyRun",
        "asec.ahnlab.com": "ASEC AhnLab",
        "jfrog.com": "JFrog",
        "nextron-systems.com": "Nextron Systems",
        "opensourcemalware.com": "OpenSource Malware",
        "infostealers.com": "Infostealers",
        "breakglass.tech": "BreakGlass Intel",
        "intel.breakglass.tech": "BreakGlass Intel",
        "malwarebytes.com": "Malwarebytes",
        "hunt.io": "Hunt.io",
        "anomali.com": "Anomali",
        "reversinglabs.com": "ReversingLabs",
        "infoblox.com": "Infoblox",
        "flare.io": "Flare.io",
        "socradar.io": "SOCRadar",
        "mp.weixin.qq.com": "WeChat Security",
        "securityboulevard.com": "Security Boulevard",
        "antiy.cn": "Antiy Response",
        "antiy.com": "Antiy Response",
        "lac.co.jp": "LAC Watch",
        "jamf.com": "Jamf",
        "foxitsecurity.wpcomstaging.com": "Foxit",
        "logpresso.com": "Logpresso",
        "securityscorecard.com": "SecurityScorecard",
        "allsecure.io": "AllSecure",
        "daylight.ai": "Daylight Security",
        "enki.co.kr": "Enki",
        "safedep.io": "SafeDep",
        "sonatype.com": "Sonatype",
        "checkmarx.com": "Checkmarx",
        "socket.dev": "Socket.dev",
        "nccgroup.com": "NCC Group",
        "forcepoint.com": "Forcepoint",
        "huntress.com": "Huntress",
        "sekoia.io": "Sekoia",
        "intezer.com": "Intezer",
        "polyswarm.io": "PolySwarm",
        "avertium.com": "Avertium",
        "fieldeffect.com": "Field Effect",
        "securityjoes.com": "Security Joes",
        "gbhackers.com": "GBHackers",
        "denwp.com": "DenWP",
        "kmsec.uk": "KM Sec",
        "threatbook.io": "ThreatBook",
        "cyberpress.org": "CyberPress",
        "cybereason.com": "Cybereason",
        "cloudsek.com": "CloudSEK",
        "cyble.com": "Cyble",
        "recordedfuture.com": "Recorded Future",
        "greynoise.io": "GreyNoise",
        "zscaler.com": "Zscaler",
        "morphisec.com": "Morphisec",
        "isc.sans.edu": "SANS ISC",
        "cert.pl": "Cert PL",
        "wordfence.com": "Wordfence",
        "acronis.com": "Acronis",
        "unit42.paloaltonetworks.com": "Unit 42",
        "research.checkpoint.com": "CheckPoint Research",
        "blog.talosintelligence.com": "Talos Intel",
        "crowdstrike.com": "CrowdStrike",
        "sentinelone.com": "SentinelOne",
        "volexity.com": "Volexity",
        "elastic.co": "Elastic Security",
        "rapid7.com": "Rapid7",
        "fortinet.com": "Fortinet",
        "trendmicro.com": "Trend Micro",
        "proofpoint.com": "Proofpoint",
        "blog.cloudflare.com": "Cloudflare",
        "akamai.com": "Akamai",
        "microsoft.com": "Microsoft Security",
        "secrss.com": "SecRSS",
        "ctfiot.com": "CTFiot",
        "nsfocusglobal.com": "NSFocus",
        "slowmist.medium.com": "SlowMist",
        "osintteam.blog": "OSINT Team",
        "systemweakness.com": "System Weakness",
        "infosecwriteups.com": "InfoSec Writeups",
        "arcticwolf.com": "Arctic Wolf",
        "hackread.com": "HackRead",
        "moonlock.com": "Moonlock",
        "horizon3.ai": "Horizon3 AI",
        "d3lab.net": "D3Lab",
        "cyberaccord.com": "CyberAccord",
        "seqrite.com": "Seqrite",
        "blog.xlab.qianxin.com": "Qianxin XLab",
        "ti.qianxin.com": "Qianxin TI",
        "sophos.com": "Naked Security",
        "blogs.cisco.com": "Cisco Security",
        "helpnetsecurity.com": "Help Net Security",
        "grahamcluley.com": "Graham Cluley",
        "schneier.com": "Schneier on Security",
        "troyhunt.com": "Troy Hunt",
        "codeaintel.com": "Codea Intel",
        "blog-wp.darkatlas.io": "Dark Atlas",
        "hybrid-analysis.blogspot.com": "Hybrid Analysis",
        "rewterz.com": "Rewterz",
        "blog.epiphany-consulting.net": "Epiphany Consulting",
        "blog.lukeacha.com": "Luke Acha",
        "dmpdump.github.io": "DMpDump",
        "posts.inthecyber.com": "InTheCyber",
        "qurium.org": "Qurium",
        "sect.iij.ad.jp": "IIJ SEC",
        "bfore.ai": "Bfore AI",
        "ox.security": "Ox Security",
        "silentpush.com": "Silentpush",
        "domaintools.com": "DomainTools",
        "group-ib.com": "Group-IB",
        "blog.knowbe4.com": "KnowBe4",
        "mimecast.com": "Mimecast",
        "labs.k7computing.com": "K7 Labs",
        "cyberint.com": "Cyberint",
        "blog.deception.pro": "Deception.Pro",
        "the-hunters-ledger.com": "Hunter's Ledger",
        "picussecurity.com": "Picus Security",
        "reliaquest.com": "ReliaQuest",
        "levelblue.com": "LevelBlue",
        "esentire.com": "eSentire",
        "cloudsek.com": "CloudSEK",
        "security.com": "Security.com Threat Intel",
        "malwareanalysisspace.blogspot.com": "Malware Analysis Space",
        "expel.com": "Expel",
        "fieldeffect.com": "Field Effect",
        "gbhackers.com": "GBHackers",
        "denwp.com": "DenWP",
        "securityscorecard.com": "SecurityScorecard",
        "sekoia.com": "Sekoia",
        "validin.com": "Validin",
    }

    for domain, name in sorted(SOURCE_DOMAINS.items(), key=lambda x: -len(x[0])):
        if domain in url:
            return name

    # 回退：提取主域名，排除明显不是来源名的短词
    m = re.search(r'https?://([^/]+)', url)
    if m:
        domain = m.group(1).replace("www.", "")
        # 去掉 .com/.org/.net 等后缀，取可读名称
        domain_base = re.sub(r'\.[a-z]{2,}(\.[a-z]{2})?$', '', domain)
        # 用点分隔取主名称
        parts = domain_base.split(".")
        # 过滤掉像 "mp", "blog", "www", "mail" 等前缀
        useful = [p for p in parts if p not in (
            "mp", "blog", "www", "mail", "new", "old", "m",
            "www2", "www3", "ww2", "ww3", "api", "news",
            "feeds", "feed", "rss", "post", "posts",
        )]
        if useful:
            return useful[-1].title()

    return "Security Blog"


def _clean_url(url):
    url = re.sub(r'[),.;:`\'"\\\s]+$', "", url)
    if re.search(r"\$\{|<[A-Za-z_]", url):
        return None
    low = url.lower()
    if any(x in low for x in EXCLUDE_URL_SUBSTRINGS):
        return None
    if not (url.startswith("http://") or url.startswith("https://")):
        return None
    return url


def _tag_text(tag):
    if isinstance(tag, dict):
        return str(tag.get("value") or tag.get("name") or "").strip()
    return str(tag).strip() if tag else ""


def clean_tags(tags):
    cleaned = []
    for tag in tags or []:
        text = _tag_text(tag)
        if not text:
            continue
        if text.lower() in GENERIC_NOISE_TAGS:
            continue
        if text not in cleaned:
            cleaned.append(text)
    return cleaned


def clean_value(ioc_type, raw_value):
    """清洗单个 IOC 值，无效返回 None"""
    if not raw_value:
        return None

    value = raw_value.strip()
    if not value:
        return None

    # defanged 清理
    if ioc_type in ("url", "domain"):
        cleaned = clean_defanged_value(value)
        if cleaned is None:
            return None
        value = cleaned

    value_lower = value.lower()

    # 类型校验
    if ioc_type == "ip":
        return value if is_valid_ip(value_lower) else None
    elif ioc_type == "domain":
        return value if is_valid_domain(value_lower) else None
    elif ioc_type in ("sha256", "md5", "sha1"):
        return value_lower if is_valid_hash(ioc_type, value_lower) else None
    elif ioc_type == "url":
        return _clean_url(value)
    else:
        return value


def load_derp_iocs():
    """加载 derp.ca C2 / 研究文章 IOC"""
    result = []
    items = load_json_files("all_iocs_*.json", os.path.join(HISTORY_DIR, "derp"))
    items.extend(load_json_files("derp_all_iocs_*.json", SCRIPTS_DIR))
    for item in items:
        ioc_type = (item.get("type") or "").lower()
        ioc_value = (item.get("value") or "").strip()
        if ioc_type not in KEEP_TYPES or not ioc_value:
            continue
        result.append({
            "type": ioc_type,
            "value": ioc_value,
            "source": item.get("source") or "derp.ca",
            "url": item.get("source_url") or item.get("url") or "",
            "title": item.get("title") or "",
            "threat_actors": list(item.get("threat_actors") or []),
            "malware": list(item.get("malware") or []),
            "crawl_time": item.get("crawl_time") or "",
        })
    return result


def merge_ioc_list(merged, items):
    for ioc in items:
        key = f"{ioc['type']}|{ioc['value']}"
        if key in merged:
            existing = merged[key]
            for ta in ioc.get("threat_actors", []):
                if ta and ta not in existing["threat_actors"]:
                    existing["threat_actors"].append(ta)
            for m in ioc.get("malware", []):
                if m and m not in existing["malware"]:
                    existing["malware"].append(m)
            if ioc.get("source") and not existing.get("source"):
                existing["source"] = ioc["source"]
            if ioc.get("url") and not existing.get("url"):
                existing["url"] = ioc["url"]
        else:
            merged[key] = ioc
    return merged


# ============================================================
# 主逻辑
# ============================================================

def main():
    print("=" * 60)
    print("IOC 汇总导出工具 v2")
    print("直接从原始数据源汇总，不经过降质 merge 路径")
    print("=" * 60)

    # 1. 加载所有数据源
    print("\n[1] 加载数据源...")
    rss_iocs, _seen_keys = load_rss_iocs()
    print(f"    RSS IOCs: {len(rss_iocs)} 条")

    apt_iocs = load_apt_iocs()
    print(f"    APT IOCs: {len(apt_iocs)} 条（含 intel 补填 TA）")

    derp_iocs = load_derp_iocs()
    print(f"    derp IOCs: {len(derp_iocs)} 条")

    merged = {}
    merge_ioc_list(merged, rss_iocs)
    merge_ioc_list(merged, apt_iocs)
    merge_ioc_list(merged, derp_iocs)

    all_iocs = list(merged.values())
    print(f"    合并后: {len(all_iocs)} 条")

    # 3. 清洗
    print("\n[2] 清洗 IOC...")
    cleaned = []
    removed = {"ip": 0, "domain": 0, "hash": 0, "url": 0, "other": 0}

    for ioc in all_iocs:
        clean_val = clean_value(ioc["type"], ioc["value"])
        if clean_val is None:
            removed[ioc["type"]] = removed.get(ioc["type"], 0) + 1
            continue

        ioc["value"] = clean_val
        ioc["threat_actors"] = clean_tags(ioc.get("threat_actors"))
        ioc["malware"] = clean_tags(ioc.get("malware"))
        cleaned.append(ioc)

    # 清洗后值去重（保留第一个）
    seen_clean = set()
    final_iocs = []
    for ioc in cleaned:
        key = f"{ioc['type']}|{ioc['value']}"
        if key not in seen_clean:
            seen_clean.add(key)
            final_iocs.append(ioc)

    total_removed = sum(removed.values())
    print(f"    移除: {total_removed} 条 ({removed})")
    print(f"    清洗后: {len(final_iocs)} 条")

    # 4. 统计
    by_type = defaultdict(int)
    for ioc in final_iocs:
        by_type[ioc["type"]] += 1

    with_ta = sum(1 for i in final_iocs if i.get("threat_actors"))
    with_mw = sum(1 for i in final_iocs if i.get("malware"))

    print(f"\n[3] 统计:")
    print(f"    总数: {len(final_iocs)}")
    print(f"    有威胁行为者: {with_ta}")
    print(f"    有恶意软件: {with_mw}")
    for t in ["ip", "domain", "sha256", "md5", "sha1", "url"]:
        print(f"    {t}: {by_type.get(t, 0)}")

    # 来源分布
    source_count = defaultdict(int)
    for ioc in final_iocs:
        source_count[ioc.get("source", "未知")] += 1
    print(f"\n    来源分布 TOP:")
    for s, c in sorted(source_count.items(), key=lambda x: -x[1])[:15]:
        print(f"      {c:5d}  {s}")

    # 5. 保存
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 简洁版（按类型分组）
    grouped = {}
    for t in KEEP_TYPES:
        grouped[t] = [ioc["value"] for ioc in final_iocs if ioc["type"] == t]

    latest = {
        "timestamp": timestamp,
        "total": len(final_iocs),
        "by_type": dict(by_type),
        "with_threat_actors": with_ta,
        "with_malware": with_mw,
        "iocs": grouped,
    }
    latest_path = os.path.join(OUTPUT_DIR, "all_iocs_latest.json")
    with open(latest_path, "w", encoding="utf-8") as f:
        json.dump(latest, f, ensure_ascii=False, indent=2)
    print(f"\n[4] 保存:")
    print(f"    {latest_path}")

    # 明细版
    detail = {
        "timestamp": timestamp,
        "total": len(final_iocs),
        "by_type": dict(by_type),
        "with_threat_actors": with_ta,
        "with_malware": with_mw,
        "iocs": final_iocs,
    }
    detail_path = os.path.join(OUTPUT_DIR, f"all_iocs_detail_{timestamp}.json")
    with open(detail_path, "w", encoding="utf-8") as f:
        json.dump(detail, f, ensure_ascii=False, indent=2)
    print(f"    {detail_path}")

    # 威胁行为者 TOP
    ta_count = defaultdict(int)
    mw_count = defaultdict(int)
    for ioc in final_iocs:
        for ta in ioc.get("threat_actors", []):
            if ta:
                ta_count[ta] += 1
        for m in ioc.get("malware", []):
            if m:
                mw_count[m] += 1

    print(f"\n[5] 威胁行为者 TOP:")
    for ta, c in sorted(ta_count.items(), key=lambda x: -x[1])[:15]:
        print(f"    {ta}: {c}")
    print(f"\n    恶意软件 TOP:")
    for m, c in sorted(mw_count.items(), key=lambda x: -x[1])[:15]:
        print(f"    {m}: {c}")

    print(f"\n{'='*60}")
    print(f"完成!")
    print(f"{'='*60}")
    return {
        "total": len(final_iocs),
        "with_ta": with_ta,
        "with_mw": with_mw,
        "file": detail_path,
    }


if __name__ == "__main__":
    main()
