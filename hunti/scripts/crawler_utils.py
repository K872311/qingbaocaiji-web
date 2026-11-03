"""
爬虫历史状态管理公用模块

提供统一的:
  - 历史数据文件存储 (output/history/<module>/)
  - 状态指纹去重
  - delta 增量追踪
  - IOC 值校验（采集端与导出端共用，避免两边规则漂移）
"""
import json, os, re, hashlib, glob
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HISTORY_DIR = os.path.join(BASE_DIR, "output", "history")
STATE_DIR = os.path.join(BASE_DIR, "output", "history_state")
os.makedirs(HISTORY_DIR, exist_ok=True)
os.makedirs(STATE_DIR, exist_ok=True)


def load_otx_api_key() -> str:
    """OTX API Key：OTX_API_KEY / ALIENVAULT_OTX_KEY，或 config/otx_api_key.txt。"""
    for env in ("OTX_API_KEY", "ALIENVAULT_OTX_KEY", "OTX_KEY"):
        key = os.environ.get(env, "").strip()
        if key:
            return key
    for path in (
        os.path.join(BASE_DIR, "config", "otx_api_key.txt"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "otx_api_key.txt"),
    ):
        key = _first_noncomment_line(path)
        if key and "your_otx_api_key" not in key.lower():
            return key
    return ""


def load_tc_feed_token() -> str:
    """ThreatCluster Key：TC_KEY / TC_FEED_TOKEN，或 config/tc_feed_token.txt。"""
    for env in ("TC_KEY", "TC_API_KEY", "TC_FEED_TOKEN"):
        key = os.environ.get(env, "").strip()
        if key:
            return key
    candidates = [
        os.path.join(BASE_DIR, "config", "tc_api_key.txt"),
        os.path.join(BASE_DIR, "config", "tc_feed_token.txt"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "tc_feed_token.txt"),
    ]
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        return line
        except OSError:
            continue
    return ""


def _first_noncomment_line(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    except OSError:
        return ""
    return ""


def load_threatfox_auth_key() -> str:
    """ThreatFox Auth-Key：THREATFOX_AUTH_KEY / ABUSECH_AUTH_KEY，或 config/threatfox_auth_key.txt。"""
    for env in ("THREATFOX_AUTH_KEY", "ABUSECH_AUTH_KEY"):
        key = os.environ.get(env, "").strip()
        if key:
            return key
    for path in (
        os.path.join(BASE_DIR, "config", "threatfox_auth_key.txt"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "threatfox_auth_key.txt"),
    ):
        key = _first_noncomment_line(path)
        if key and "your_threatfox" not in key.lower():
            return key
    return ""


def module_history_dir(module_name: str) -> str:
    """返回模块专属的历史文件夹路径"""
    d = os.path.join(HISTORY_DIR, module_name)
    os.makedirs(d, exist_ok=True)
    return d


def state_file_path(module_name: str) -> str:
    return os.path.join(STATE_DIR, f"{module_name}_state.json")


def load_state(module_name: str) -> dict:
    """加载模块的去重状态文件"""
    path = state_file_path(module_name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"seen_fingerprints": {}, "total_accumulated": 0, "first_crawl": None, "last_crawl": None}


def save_state(module_name: str, state: dict):
    """保存模块的去重状态文件"""
    state["last_crawl"] = datetime.now().isoformat()
    if state.get("first_crawl") is None:
        state["first_crawl"] = state["last_crawl"]
    path = state_file_path(module_name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def fingerprint(*parts) -> str:
    """生成去重指纹（对任意字符串组合取 MD5）"""
    raw = "|".join(str(p).strip().lower() for p in parts)
    return hashlib.md5(raw.encode()).hexdigest()


def url_fingerprint(url: str) -> str:
    """
    文章去重指纹：只认 URL，忽略标题。

    标题在 RSS feed 和博客首页两条发现路径下取值不同（真标题 vs 站点名），
    参与哈希会让同一篇文章产生两个指纹、被重复下载。
    同时归一化 scheme/www/末尾斜杠/追踪参数，避免同一文章多种写法。
    """
    u = (url or "").strip()
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    try:
        parts = urlsplit(u.lower())
    except ValueError:
        return hashlib.md5(u.lower().encode()).hexdigest()
    host = parts.netloc.split("@")[-1]
    if host.startswith("www."):
        host = host[4:]
    host = host.replace(":80", "").replace(":443", "")
    path = parts.path.rstrip("/")
    query = "&".join(
        q for q in sorted(parts.query.split("&"))
        if q and not q.split("=")[0].startswith(("utm_", "fbclid", "gclid", "ref"))
    )
    normalized = urlunsplit(("", host, path, query, ""))
    return hashlib.md5(normalized.encode()).hexdigest()


# ============================================================
# IOC 值校验 —— 采集端与导出端共用
# ============================================================

VALID_TLDS = {
    "com", "org", "net", "io", "co", "me", "info", "biz",
    "online", "tech", "xyz", "top", "site", "win", "work",
    "dev", "app", "shop", "store", "cloud", "live", "life",
    "click", "link", "space", "website", "fun", "icu", "cc",
    "pw", "sbs", "cfd", "bond", "rest", "claims", "quest",
    "cn", "jp", "kr", "tw", "hk", "au", "uk", "eu", "ru",
    "de", "fr", "us", "ca", "nl", "se", "no", "dk", "fi",
    "pl", "it", "es", "pt", "br", "za", "sg", "my", "in",
    "id", "vn", "th", "ph", "ae", "sa", "by", "kz", "uz",
    "md", "bg", "ro", "hu", "cz", "sk", "at", "ch", "be",
    "lu", "ie", "gr", "cy", "mt", "si", "hr", "ba", "rs",
    "mk", "al", "lv", "lt", "ee", "ws", "su", "tk", "ml",
    "ga", "cf", "gg", "to", "tv", "ir", "tr", "ua", "il",
    "mx", "cl", "ar", "pe", "ng", "ke", "eg", "onion",
    "forum", "today", "club", "one", "vip",
    "lol", "cyou", "email", "digital", "world", "pro",
    "page", "blog", "news", "group", "company", "network",
    "host", "cam", "pics", "loan", "agency", "guru",
}
# 注意：不把 zip/mov/js 等常见文件后缀放进 TLD，避免 FCCCall.msi / foo.zip / Node.js 被当成域名

# 文件名误抽成域名（扩展名）
FILE_LIKE_SUFFIXES = (
    ".exe", ".dll", ".sys", ".so", ".dylib", ".msi", ".dmg", ".pkg", ".appx", ".msix",
    ".bat", ".cmd", ".ps1", ".vbs", ".js", ".ts", ".jsx", ".mjs", ".cjs",
    ".py", ".pyc", ".go", ".rs", ".java", ".class", ".jar", ".war",
    ".sh", ".bash", ".zsh", ".ahk",
    ".md", ".txt", ".json", ".xml", ".csv", ".yaml", ".yml", ".toml",
    ".cfg", ".conf", ".ini", ".log", ".lock",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".zip", ".tar", ".gz", ".rar", ".7z", ".iso",
    ".pdb", ".pdf", ".docx", ".xlsx", ".doc", ".xls", ".ppt", ".pptx",
    ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".wasm",
    ".lnk", ".cpl", ".scr",
)

# 情报文里常见的「来源站 / 平台 / 工具站」，单独出现时不是 IOC
DEFAULT_NOISE_HOSTS = (
    "mp.weixin.qq.com", "weixin.qq.com", "qq.com",
    "github.com", "www.github.com", "githubusercontent.com", "raw.githubusercontent.com", "gist.github.com",
    "gitlab.com", "bitbucket.org", "npmjs.com", "npmjs.org", "pypi.org", "nuget.org",
    "twitter.com", "x.com", "facebook.com", "linkedin.com", "youtube.com", "medium.com",
    "blogspot.com", "wordpress.com", "wikipedia.org",
    "group-ib.com", "www.group-ib.com", "blog.phylum.io", "phylum.io",
    "virustotal.com", "any.run", "hybrid-analysis.com", "tria.ge", "urlscan.io",
    "abuse.ch", "threatfox.abuse.ch", "bazaar.abuse.ch", "urlhaus.abuse.ch",
    "microsoft.com", "google.com", "cloudflare.com", "amazon.com", "amazonaws.com",
    "apple.com", "schema.org", "w3.org", "ietf.org", "mitre.org",
    "thehackernews.com", "bleepingcomputer.com", "krebsonsecurity.com",
    "sentinelone.com", "crowdstrike.com", "securelist.com", "securelist.ru",
    "welivesecurity.com", "sysdig.com", "www.sysdig.com",
    "unit42.paloaltonetworks.com", "research.checkpoint.com",
    "ctfiot.com", "www.ctfiot.com", "threatbook.cn", "threatbook.io",
    "t.me", "telegram.me", "pastebin.com",
    "example.com", "example.net", "example.org",
)

# 安全厂商 / 安全媒体 / 政府 CERT：文章正文里引用的报告链接不是 IOC。
# 例：Anomali、Wiz 的博客引用 Symantec 报告 www.security.com/threat-intelligence/...，
# 被 RSS 抽成「恶意 URL」带上 APT41 标签。
SECURITY_REPORT_HOSTS = (
    # 厂商研究博客
    "security.com", "symantec.com", "broadcom.com", "symantec-enterprise-blogs.security.com",
    "kaspersky.com", "trendmicro.com", "mandiant.com", "fireeye.com", "paloaltonetworks.com",
    "fortinet.com", "fortiguard.com", "sophos.com", "eset.com", "mcafee.com", "trellix.com",
    "cisco.com", "talosintelligence.com", "malwarebytes.com", "bitdefender.com", "avast.com",
    "gendigital.com", "norton.com", "f-secure.com", "withsecure.com", "zscaler.com", "netskope.com",
    "akamai.com", "imperva.com", "darktrace.com", "recordedfuture.com", "intezer.com",
    "cybereason.com", "wiz.io", "anomali.com", "sekoia.io", "lab52.io", "cyble.com", "socradar.io",
    "dragos.com", "claroty.com", "nozominetworks.com", "redcanary.com", "volexity.com",
    "eclecticiq.com", "threatfabric.com", "zimperium.com", "lookout.com", "checkmarx.com",
    "sonatype.com", "socket.dev", "aquasec.com", "datadoghq.com", "elastic.co", "ptsecurity.com",
    "bi.zone", "nccgroup.com", "trustwave.com", "varonis.com", "arcticwolf.com", "blackberry.com",
    "secureworks.com", "securityintelligence.com", "ibm.com", "rapid7.com", "tenable.com",
    "qualys.com", "checkpoint.com", "cloudsek.com", "seqrite.com", "quickheal.com",
    "kelacyber.com", "flashpoint.io", "intel471.com", "binarydefense.com", "huntress.com",
    "sentinelone.com", "crowdstrike.com", "proofpoint.com", "cofense.com", "abnormalsecurity.com",
    "levelblue.com", "trustwave.com", "esentire.com", "deepinstinct.com", "harfanglab.io",
    "orangecyberdefense.com", "certfa.com", "silentpush.com", "censys.com", "shodan.io",
    "greynoise.io", "domaintools.com", "team-cymru.com", "spamhaus.org", "shadowserver.org",
    # 国内厂商 / 媒体
    "qianxin.com", "360.net", "360.cn", "antiy.com", "antiy.cn", "nsfocus.com", "venustech.com.cn",
    "sangfor.com", "sangfor.com.cn", "tencent.com", "freebuf.com", "anquanke.com", "4hou.com",
    "seebug.org", "secrss.com", "knownsec.com", "dbappsecurity.com.cn", "huorong.cn", "rising.com.cn",
    # 安全媒体 / 新闻
    "securityweek.com", "darkreading.com", "infosecurity-magazine.com", "scmagazine.com",
    "helpnetsecurity.com", "securityaffairs.com", "csoonline.com", "cyberscoop.com", "wired.com",
    "zdnet.com", "techcrunch.com", "nytimes.com", "washingtonpost.com", "bbc.co.uk", "bbc.com",
    "hackread.com", "gbhackers.com", "cybersecuritynews.com", "thecyberexpress.com", "therecord.media",
    "theregister.com", "arstechnica.com", "reuters.com", "bloomberg.com", "databreaches.net",
    "bankinfosecurity.com", "govinfosecurity.com", "industrialcyber.co", "cybernews.com",
    # 政府 / CERT / 标准
    "cisa.gov", "us-cert.gov", "ic3.gov", "fbi.gov", "justice.gov", "ncsc.gov.uk", "cert.org",
    "nist.gov", "cve.org", "cert.pl", "jpcert.or.jp", "cert.ssi.gouv.fr", "bsi.bund.de",
    "cyber.gov.au", "canada.ca", "cert-in.org.in", "enisa.europa.eu", "europol.europa.eu",
)


def is_report_host(host: str) -> bool:
    """主机是否属于安全厂商 / 媒体 / CERT 站点（文章引用，不是 IOC）。"""
    h = (host or "").strip().lower().rstrip(".")
    return bool(h) and domain_matches_exclusion(h, SECURITY_REPORT_HOSTS + DEFAULT_NOISE_HOSTS)


DEFAULT_NOISE_HOSTS = DEFAULT_NOISE_HOSTS + SECURITY_REPORT_HOSTS

PLACEHOLDER_IPS = {
    "1.1.1.1", "1.2.3.1", "1.2.3.4", "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "4.2.2.1", "4.2.2.2",
    "208.67.222.222", "208.67.220.220",
}


def is_valid_ip(value: str) -> bool:
    """公网单播 IPv4 校验。允许 ip:port 写法，端口会被忽略。"""
    ip = (value or "").strip().split(":")[0]
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    if not m:
        return False
    o = [int(m.group(i)) for i in range(1, 5)]
    if any(p > 255 for p in o):
        return False
    # 私有 / 环回 / 链路本地 / 保留
    if o[0] in (0, 10, 127):
        return False
    if o[0] == 192 and o[1] == 168:
        return False
    if o[0] == 172 and 16 <= o[1] <= 31:
        return False
    if o[0] == 169 and o[1] == 254:
        return False
    if o[0] == 100 and 64 <= o[1] <= 127:
        return False
    # 组播 / 广播 / 保留高段
    if o[0] >= 224:
        return False
    # 文档示例网段 (RFC 5737)
    if (o[0], o[1], o[2]) in ((192, 0, 2), (198, 51, 100), (203, 0, 113)):
        return False
    if o[0] == 198 and o[1] in (18, 19):
        return False
    # 网络地址 / 广播地址：x.x.x.0 与 x.x.x.255 不是可用主机地址
    if o[3] in (0, 255):
        return False
    if ".".join(str(p) for p in o) in PLACEHOLDER_IPS:
        return False
    return True


def is_valid_hash(hash_type: str, value: str) -> bool:
    lengths = {"md5": 32, "sha1": 40, "sha256": 64}
    n = lengths.get((hash_type or "").lower())
    if not n:
        return False
    return re.match(r"^[a-f0-9]{%d}$" % n, (value or "").strip().lower()) is not None


def domain_matches_exclusion(domain: str, patterns) -> bool:
    """
    判断域名是否命中排除表。

    必须按边界匹配，不能用裸子串 `in`：排除表里有 "main."、".sh"、"t.co"
    这类短模式，子串匹配会误杀 malicious-domain.top（含 "main."）、
    fake.shop（含 ".sh"）、以及任意 *t.com（含 "t.co"）。

    规则：
      - 以 "." 开头（.exe / .ac.uk）→ 视为后缀，按 endswith 匹配
      - 以 "." 结尾（main. / node.）→ 代码属性访问，要求它是完整标签前缀
      - 含 "." 的完整域名（google.com）→ 相等或作为子域后缀命中
      - 不含 "." 的裸词（hetzner）→ 匹配任一完整标签
    """
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return False
    labels = d.split(".")
    for raw in patterns:
        p = (raw or "").strip().lower()
        if not p:
            continue
        if p.startswith("."):
            if d.endswith(p):
                return True
        elif p.endswith("."):
            # "main." 只在 d 以 "main." 起头时算命中，不匹配 "...-domain.top"
            if d.startswith(p):
                return True
        elif "." in p:
            if d == p or d.endswith("." + p):
                return True
        else:
            if p in labels:
                return True
    return False


_SLD_SUFFIX_LABELS = {"com", "net", "org", "gov", "edu", "co", "ac", "or", "ne", "go", "mil"}


def is_valid_domain(value: str, exclude_substrings=(), exclude_exact=()) -> bool:
    """
    域名校验。核心是 TLD 白名单——这是拒绝代码片段（Trainer.asi、d.ZPa、
    config.json）被当成域名的唯一可靠手段，正则本身无法区分。
    """
    d = (value or "").strip().lower().rstrip(".")
    if len(d) < 5 or "." not in d:
        return False
    # 文件名误抽：FCCCall.msi / setup.exe / Node.js
    if d.endswith(FILE_LIKE_SUFFIXES):
        return False
    if d in {e.lower() for e in exclude_exact}:
        return False
    noise = tuple(exclude_substrings) + DEFAULT_NOISE_HOSTS
    if domain_matches_exclusion(d, noise):
        return False

    parts = d.split(".")
    if len(parts) < 2 or len(parts) > 5:
        return False

    # 每一段必须是合法 LDH 标签（拒绝 Node.js 里的大小写混写已 lower）
    for p in parts:
        if not p or len(p) > 63:
            return False
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", p):
            return False

    # 纯 IP 形态不是域名
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", d):
        return False

    # TLD 白名单
    if parts[-1] not in VALID_TLDS:
        return False

    # 单字母子域 / 数字开头子域 通常是代码引用或 IP 段
    for p in parts[:-1]:
        if len(p) == 1 or p[0].isdigit():
            return False

    # 主域名（去 TLD 与 www）过短说明信息量不足
    main = [p for p in parts[:-1] if p not in ("www", "ww2", "ww3")]
    if not main or len(".".join(main)) < 3:
        return False

    # com.cn / co.uk 这类公共后缀本身不是可注册域名
    if len(parts) == 2 and parts[0] in _SLD_SUFFIX_LABELS:
        return False

    # 反向包名结构（com.foo.bar.baz）是代码引用
    if len(parts) >= 4 and parts[0] in ("com", "org", "net", "io", "co", "app"):
        return False

    return True


_CJK_CUT = re.compile(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]")
_URL_JUNK = ("<", ">", "...", "%userprofile%", "%temp%", "%appdata%", "它是", "保存为")


def clean_extracted_url(url: str) -> str:
    """去掉粘在 IOC 后面的中文说明、多余标点；无效则返回空串。"""
    u = refang_text(url or "").strip()
    if not u:
        return ""
    m = _CJK_CUT.search(u)
    if m:
        u = u[: m.start()]
    # 空白后是正文
    if re.search(r"\s", u):
        u = re.split(r"\s+", u, 1)[0]
    u = u.rstrip(").,;:，、\"']}〉》")
    while u and u[-1] in "([{（【":
        u = u[:-1]
    if not re.match(r"^https?://", u, re.I):
        return ""
    if len(u) < 12 or len(u) > 400:
        return ""
    low = u.lower()
    if any(j in low for j in _URL_JUNK):
        return ""
    try:
        parts = urlsplit(u)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if not host:
        return ""
    # 主机要么是公网 IP，要么是通过校验的域名
    if not (is_valid_ip(host) or is_valid_domain(host)):
        return ""
    # 重建，丢掉 fragment
    try:
        return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "", parts.query, ""))
    except ValueError:
        return ""


def is_noise_host(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return True
    return domain_matches_exclusion(h, DEFAULT_NOISE_HOSTS)


# ============================================================
# IOC 抽取 —— 采集端共用（含半去括号 / hxxp）
# ============================================================

_IOC_PATTERNS = {
    "ip": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    ),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
}


def refang_text(text: str) -> str:
    """
    把博客里常见的去括号写法还原，再交给普通 IOC 正则。

    覆盖：
      81.177.32[.]12 / 81[.]177[.]32[.]12
      evil[.]com / vks.gossopka[.]forum
      https://evil[.]com/path
      hxxp:// / hxxps[:]//
      (.)  {.}  [:]
    """
    t = text or ""
    t = re.sub(r"\[\s*\.\s*\]", ".", t)
    t = re.sub(r"\(\s*\.\s*\)", ".", t)
    t = re.sub(r"\{\s*\.\s*\}", ".", t)
    t = re.sub(r"\[\s*:\s*\]", ":", t)
    t = re.sub(r"(?i)\bhxxp(s?)", lambda m: "http" + m.group(1).lower(), t)
    return t


def extract_iocs(text, extra_patterns=None, valid_ip=None, valid_domain=None, valid_url=None):
    """从正文提取网络 IOC。默认先 refang，再校验（未传校验器时用内置规则）。"""
    text = refang_text(text)
    patterns = dict(_IOC_PATTERNS)
    if extra_patterns:
        patterns.update(extra_patterns)

    _vip = valid_ip or is_valid_ip
    _vd = valid_domain or (lambda d: is_valid_domain(d))
    _vu = valid_url  # URL 另有 clean + host 校验

    iocs = {}
    for ioc_type, pattern in patterns.items():
        matches = pattern.findall(text)
        if not matches:
            continue
        vals = []
        seen = set()
        for raw in matches:
            v = raw.strip().rstrip(").,;\"'")
            if not v:
                continue
            if ioc_type == "url":
                v = clean_extracted_url(v)
                if not v:
                    continue
                if _vu and not _vu(v):
                    continue
            elif ioc_type == "ip":
                if not _vip(v):
                    continue
            elif ioc_type == "domain":
                if not _vd(v):
                    continue
            elif ioc_type in ("md5", "sha1", "sha256"):
                if not is_valid_hash(ioc_type, v):
                    continue
                v = v.lower()
            key = v.lower()
            if key in seen:
                continue
            seen.add(key)
            vals.append(v)
        if vals:
            iocs[ioc_type] = vals
    return sanitize_ioc_dict(iocs)


def sanitize_ioc_dict(iocs, article_url=""):
    """清洗已落盘的文章 IOC（面板加载 / 二次处理共用）。"""
    if not isinstance(iocs, dict):
        return {}
    art_host = ""
    if article_url:
        try:
            art_host = (urlsplit(article_url).hostname or "").lower()
        except ValueError:
            art_host = ""

    out = {}
    for t, vals in iocs.items():
        if not isinstance(vals, (list, tuple)):
            continue
        bucket, seen = [], set()
        for raw in vals:
            v = str(raw or "").strip()
            if not v:
                continue
            if t == "url":
                v = clean_extracted_url(v)
                if not v:
                    continue
                try:
                    host = (urlsplit(v).hostname or "").lower()
                except ValueError:
                    continue
                if art_host and (host == art_host or host.endswith("." + art_host)):
                    continue
            elif t == "domain":
                v = refang_text(v).strip().lower().rstrip(".")
                if not is_valid_domain(v):
                    continue
                if art_host and (v == art_host or art_host.endswith("." + v) or v.endswith("." + art_host)):
                    continue
            elif t == "ip":
                v = v.split("/")[0].strip()
                if not is_valid_ip(v):
                    continue
            elif t in ("md5", "sha1", "sha256"):
                if not is_valid_hash(t, v):
                    continue
                v = v.lower()
            else:
                # email/cve 等原样保留（限长）
                v = v[:200]
            key = v.lower()
            if key in seen:
                continue
            seen.add(key)
            bucket.append(v)
            if len(bucket) >= 200:
                break
        if bucket:
            out[t] = bucket
    return out


def is_new(module_name: str, fp: str) -> bool:
    """检查指纹是否是新的"""
    state = load_state(module_name)
    return fp not in state.get("seen_fingerprints", {})


def mark_seen(module_name: str, fp: str, metadata: dict = None):
    """标记指纹为已见"""
    state = load_state(module_name)
    state.setdefault("seen_fingerprints", {})
    state["seen_fingerprints"][fp] = metadata or {"seen_at": datetime.now().isoformat()}
    save_state(module_name, state)


def mark_many_seen(module_name: str, fps: list):
    """批量标记指纹"""
    state = load_state(module_name)
    state.setdefault("seen_fingerprints", {})
    state["total_accumulated"] = state.get("total_accumulated", 0) + len(fps)
    now = datetime.now().isoformat()
    for fp in fps:
        if fp not in state["seen_fingerprints"]:
            state["seen_fingerprints"][fp] = {"seen_at": now}
    save_state(module_name, state)


def save_delta(module_name: str, data: list, prefix: str = "delta") -> str:
    """将本次新增数据写入历史文件夹，返回文件路径"""
    if not data:
        return ""
    hdir = module_history_dir(module_name)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{ts}.json"
    path = os.path.join(hdir, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


def load_all_history(module_name: str) -> list:
    """加载模块历史文件夹中所有 JSON"""
    hdir = module_history_dir(module_name)
    all_data = []
    for fpath in sorted(glob.glob(os.path.join(hdir, "*.json"))):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    all_data.extend(data)
                else:
                    all_data.append(data)
        except Exception:
            pass
    return all_data


def get_history_stats(module_name: str) -> dict:
    """获取模块的历史统计信息"""
    hdir = module_history_dir(module_name)
    files = sorted(glob.glob(os.path.join(hdir, "*.json")))
    total_size = sum(os.path.getsize(f) for f in files)
    return {
        "module": module_name,
        "delta_files": len(files),
        "total_size_kb": total_size // 1024,
    }


def print_delta_summary(all_deltas: dict):
    """run_all.py 收尾用，打印本轮所有模块的增量汇总"""
    print("\n" + "=" * 60)
    print("  本轮采集增量汇总")
    print("=" * 60)
    any_data = False
    for module, info in all_deltas.items():
        count = info.get("new_count", 0)
        filepath = info.get("file", "")
        if count > 0:
            any_data = True
            print(f"  [{module}] 新增 {count} 条 → {os.path.basename(filepath)}")
        else:
            print(f"  [{module}] 无新增数据")
    if not any_data:
        print("  所有模块均无新数据")
    print("=" * 60)
