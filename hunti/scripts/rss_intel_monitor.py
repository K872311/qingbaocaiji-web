"""
RSS威胁情报监控器 v5
监控86个RSS Feed + 15个博客首页，自动发现新威胁情报文章并提取IOC

用法:
  py scripts/rss_intel_monitor.py              # RSS检查 + 下载
  py scripts/rss_intel_monitor.py --full       # RSS + URL博客爬取 + 下载
  py scripts/rss_intel_monitor.py --discover   # 只跑URL博客爬取
  py scripts/rss_intel_monitor.py --force      # 强制重新下载
  py scripts/rss_intel_monitor.py --days 30    # 只要近 30 天的文章（默认 14，0 = 不限）
  py scripts/rss_intel_monitor.py --list       # 列出所有Feed源
  py scripts/rss_intel_monitor.py --stats      # 显示监控统计
"""

import requests
import json
import re
import os
import sys
import hashlib
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from malpedia_loader import load_malpedia_keywords
from crawler_utils import (
    url_fingerprint,
    domain_matches_exclusion,
    is_valid_ip as _shared_valid_ip,
    is_valid_domain as _shared_valid_domain,
    extract_iocs as _shared_extract_iocs,
)
from export_to_db import write_iocs

# ============================================================
# 路径配置
# ============================================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
INTEL_DIR = os.path.join(OUTPUT_DIR, "intel")
IOC_DIR = os.path.join(OUTPUT_DIR, "iocs")
STATE_FILE = os.path.join(OUTPUT_DIR, "rss_monitor_state.json")

os.makedirs(INTEL_DIR, exist_ok=True)
os.makedirs(IOC_DIR, exist_ok=True)

MAX_DOWNLOAD = 80
FORCE_MAX_DOWNLOAD = 300
# 只下载近 N 天发布的文章；取不到发布时间的文章不拦。0 = 不限。
MAX_ARTICLE_AGE_DAYS = 14
MAX_CONTENT_CHARS = 200000
# 每篇文章每种类型最多保留多少条 IOC。设得太小会截断长报告的 hash 附录。
MAX_IOCS_PER_TYPE = 500
# state 里保留多少条已见 URL。老文章被挤出后会被重新下载，所以要留足。
MAX_SEEN_URLS = 30000

# ============================================================
# RSS Feed源
# ============================================================
RSS_FEEDS = {
    # === 顶级安全厂商 ===
    "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/feed",
    "SentinelOne": "https://www.sentinelone.com/blog/feed/",
    "SentinelOne Labs": "https://www.sentinelone.com/labs/feed/",
    "Unit 42": "https://unit42.paloaltonetworks.com/feed/",
    "Rapid7": "https://www.rapid7.com/blog/rss/",
    # /blog/feed 是公司综合博客；Security Labs 单独出 RSS，带全文
    "Elastic Security": "https://www.elastic.co/security-labs/rss/feed.xml",
    "CheckPoint Research": "https://research.checkpoint.com/feed/",
    "Volexity": "https://www.volexity.com/feed/",
    "Microsoft Security": "https://www.microsoft.com/en-us/security/blog/feed/",
    "Fortinet": "https://feeds.fortinet.com/fortinet/blogs",
    # https ????????http ?????
    "Trend Micro": "http://feeds.trendmicro.com/TrendMicroResearch",
    "Proofpoint": "https://www.proofpoint.com/us/rss.xml",
    "Cloudflare": "https://blog.cloudflare.com/rss/",
    "Akamai": "https://www.akamai.com/blog/rss.xml",

    # === 专业安全媒体 ===
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Cisco Talos": "https://blog.talosintelligence.com/rss/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "WeLiveSecurity": "https://www.welivesecurity.com/feed/",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Security Affairs": "https://securityaffairs.com/feed",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "CyberScoop": "https://cyberscoop.com/feed/",
    "Infosecurity Mag": "https://www.infosecurity-magazine.com/rss/news/",
    "SC World": "https://www.scworld.com/rss/",
    "CSO Online": "https://csoonline.com/feed/",
    "Daily Security Review": "https://dailysecurityreview.com/feed/",

    # === 威胁情报专业博客 ===
    "AnyRun": "https://any.run/cybersecurity-blog/feed/",
    "ASEC AhnLab": "https://asec.ahnlab.com/en/feed/",
    "JFrog": "https://jfrog.com/feed/",
    "Nextron Systems": "https://www.nextron-systems.com/feed/",
    "OpenSource Malware": "https://opensourcemalware.com/rss.xml",
    "Infostealers": "https://www.infostealers.com/feed/",
    "Securelist": "https://securelist.com/feed/",
    "BreakGlass Intel": "https://intel.breakglass.tech/rss",
    "Malwarebytes": "https://www.malwarebytes.com/blog/feed",
    "Hunter's Ledger": "https://the-hunters-ledger.com/feed.xml",
    "ReversingLabs": "https://www.reversinglabs.com/blog/rss.xml",
    "Infoblox": "https://blogs.infoblox.com/feed/",
    "Flare.io": "https://flare.io/feed",
    "SOCRadar": "https://socradar.io/feed/",
    "Cyble": "https://cyble.com/blog/feed/",
    "Recorded Future": "https://www.recordedfuture.com/feed",
    "GreyNoise": "https://www.greynoise.io/blog/rss.xml",
    "Zscaler": "https://www.zscaler.com/blogs/feeds/security-research",
    # === 开源社区情报 ===
    "SANS ISC": "https://isc.sans.edu/rssfeed_full.xml",
    "Kudelski Security": "https://kudelskisecurity.com/research/rss.xml",
    "Cert PL": "https://cert.pl/feed/",
    "Gurucul": "https://gurucul.com/feed/",
    "Wordfence": "https://www.wordfence.com/blog/feed/",
    "Acronis": "https://www.acronis.com/en-us/blog/feed.xml",

    # === 中文安全博客 ===
    "CTFiot": "https://www.ctfiot.com/feed",
    "Aliyun XZ": "https://xz.aliyun.com/feed",
    "NSFocus": "https://nsfocusglobal.com/feed/",

    # === Medium安全作者 ===
    "SlowMist": "https://slowmist.medium.com/feed",
    "OSINT Team": "https://osintteam.blog/feed",
    "System Weakness": "https://systemweakness.com/feed",
    "InfoSec Writeups": "https://infosecwriteups.com/feed",
    "DarkMoonSec": "https://medium.com/feed/@darkmoonsec",
    "SocFortress": "https://socfortress.medium.com/feed",

    # === 新增源（用户指定） ===
    "Arctic Wolf": "https://arcticwolf.com/feed/",
    "HackRead": "https://hackread.com/feed/",
    "Moonlock": "https://moonlock.com/feed",
    "Horizon3 AI": "https://horizon3.ai/feed/",
    "D3Lab": "https://www.d3lab.net/feed/",
    "Securelist RU": "https://securelist.ru/feed/",
    "Seqrite": "https://www.seqrite.com/blog/feed/",
    "Synaptic Systems": "https://blog.synapticsystems.de/feed/",
    "Qianxin XLab": "https://blog.xlab.qianxin.com/rss/",

    # === 新增源（用户第二批 2026-07）===
    # Naked Security 2023 ??????? Sophos X-Ops ??????
    "Sophos X-Ops": "https://news.sophos.com/en-us/category/threat-research/feed/",
    "Cisco Security": "https://blogs.cisco.com/security/feed",
    "Help Net Security": "https://www.helpnetsecurity.com/feed/",
    "Graham Cluley": "https://www.grahamcluley.com/feed/",
    "Schneier on Security": "https://www.schneier.com/feed/",
    "Troy Hunt": "https://www.troyhunt.com/rss/",
    "Google Online Security": "http://feeds.feedburner.com/GoogleOnlineSecurityBlog",

    # === Hunt.io 覆盖源（2026-07）===
    "Codea Intel": "https://codeaintel.com/feed/",
    "Dark Atlas": "https://blog-wp.darkatlas.io/feed/",
    "Hybrid Analysis": "https://hybrid-analysis.blogspot.com/feeds/posts/default",
    "StealthMole": "https://stealthmole-intelligence-hub.blogspot.com/feeds/posts/default",
    "Rewterz": "https://www.rewterz.com/feed",

    # === Hunt.io 覆盖源（第二批 2026-07）===
    "Epiphany Consulting": "https://blog.epiphany-consulting.net/feed/",
    "Luke Acha": "https://blog.lukeacha.com/atom.xml",
    "DMpDump": "https://dmpdump.github.io/feed.xml",
    "InTheCyber": "https://posts.inthecyber.com/feed/",
    "Qurium": "https://qurium.org/rss/",
    "IIJ SEC": "https://sect.iij.ad.jp/feed/",
    "Aikido": "https://feeds.feedburner.com/aikido",

    # === Hunt.io 覆盖源（第三批 2026-07）===
    "Bfore AI": "https://bfore.ai/feed/",
    "Ox Security": "https://ox.security/feed/",
    "Silentpush": "https://silentpush.com/feed/",
    "DomainTools": "https://rss.app/feeds/_22lRQJMKndkBEjVr.xml",

    # === APT CSV 新发现源（2026-07）===
    "Fox-IT": "https://blog.fox-it.com/feed/",
    "RedAsgard": "https://redasgard.com/rss.xml",
    "Sonatype": "https://www.sonatype.com/blog/rss.xml",
    "微步在线": "https://threatbook.io/blog/rss.xml",
    "SafeDep": "https://safedep.io/rss.xml",
    "PolySwarm": "https://blog.polyswarm.io/rss.xml",
    "KM Sec": "https://kmsec.uk/rss.xml",

    # === JPCERT（2026-07）===
    "JPCERT/CC": "https://blogs.jpcert.or.jp/en/atom.xml",

    # === ThreatNexus 补充源（2026-07）===
    "Google TAG": "https://blog.google/innovation-and-ai/technology/safety-security/rss/",
    # Google/Mandiant TI：原生 RSS 与 Feedburner 别名内容一致；双源互备（网络可达性）
    "Mandiant": "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
    "Google TI (Feedburner)": "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",
    "IBM X-Force": "https://exchange.xforce.ibmcloud.com/rss/tar",
    "IronScales": "https://ironscales.com/threat-intelligence/rss.xml",
    "The Record": "https://therecord.media/feed",
    "Wiz Research": "https://www.wiz.io/api/feed/cloud-threat-landscape/rss.xml",
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "CISA News": "https://www.cisa.gov/news.xml",
    "NCSC UK": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
    "ThreatCluster": "https://threatcluster.io/feed.xml",
    "ThreatCluster Dark Web": "https://threatcluster.io/dark-web/feed.xml",
    "ThreatCluster Vulns": "https://threatcluster.io/vulnerabilities/feed.xml",
    "ThreatCluster Exploits": "https://threatcluster.io/exploits/feed.xml",
    "Derp Malware": "https://www.derp.ca/malware/feed",
    "Derp Research": "https://www.derp.ca/research/feed",

    # === APT 硬编码列表里订阅没有的源（已验证 RSS 为 XML）===
    "Huntress": "https://www.huntress.com/blog/rss.xml",
    # Cybereason ????? LevelBlue
    "LevelBlue SpiderLabs": "https://www.levelblue.com/blogs/spiderlabs-blog/rss.xml",
    "Field Effect": "https://fieldeffect.com/blog/rss.xml",
    "Avertium": "https://www.avertium.com/blog/rss.xml",
    "K7 Labs": "https://labs.k7computing.com/index.php/feed/",
    "DenWP": "https://denwp.com/rss/",
    "SecurityScorecard": "https://securityscorecard.com/feed/",

    # === 新增源（用户第三批 2026-10）===
    # Squarespace 站点，/blog/rss.xml 会 302 到 /blog?format=rss
    "Deception.Pro": "https://blog.deception.pro/blog/rss.xml",
}

# 已有专用爬虫，RSS 再拉会占下载额度，正文经常是 Entity Not Found
RSS_SKIP_FEEDS = {
    "ThreatCluster Vulns",
    "ThreatCluster Exploits",
    "ThreatCluster Dark Web",
}

SKIP_ARTICLE_URL_SUBSTR = (
    "threatcluster.io/entities/",
    "/vulnerabilities/cve-",
    "/exploits/cve-",
)

SKIP_HOMEPAGE_SCAN = {
    "ThreatCluster",
    "ThreatCluster Dark Web",
    "ThreatCluster Vulns",
    "ThreatCluster Exploits",
    "Google TI (Feedburner)",
    "Derp Malware",
    "Derp Research",
}

# ============================================================
# URL直接爬取（补充无RSS的博客）
# ============================================================
BLOG_LISTINGS = {
    # (name, listing_url, article_link_selector)
    # --- 已验证可用（10+篇）---
    "BleepingComputer": ("https://www.bleepingcomputer.com/", "h4 a"),
    "Hunt.io": ("https://hunt.io/blog", r"regex:https://hunt\.io/blog/[A-Za-z0-9-]{8,}"),
    "CyberAndRamen": ("https://cyberandramen.net/", "h2 a"),
    "KnowBe4": ("https://blog.knowbe4.com/", "h2 a"),
    "Talos Intel": ("https://blog.talosintelligence.com/", "h2 a"),
    # --- 有文章但选择器需适配 ---
    "The Hacker News": ("https://thehackernews.com/", "a[href*='thehackernews.com/20']"),
    "Security Affairs": ("https://securityaffairs.com/", "a[href*='securityaffairs.com/']"),
    "Mimecast": ("https://www.mimecast.com/blog/", "a[href*='/blog/']"),
    # --- 用 Sitemap/替代方案 ---
    "Group-IB": ("https://www.group-ib.com/blog/", "a[href*='/blog/']"),

    # --- JS渲染站点（用正则提取URL） ---
    "Qianxin TI": ("https://ti.qianxin.com/blog/", "regex:https://ti\\.qianxin\\.com/blog/articles/[^\"<>'\\\\s]+"),
    # --- 无RSS但安全研究有价值的 ---
    "Socket.dev": ("https://socket.dev/blog", "a[href*='/blog/']:not([href*='/category/'])"),
    "Expel": ("https://expel.com/blog/category/threat-intel/", "a[href*='/blog/']"),
    # Securelist Threat Response：主站 RSS 能发现 /tr/ 文，但首次未下载会被永久跳过。
    # 栏目页兜底，避免 Head Mare / PhantomCore 这类 IOC 附录漏采。
    "Securelist TR": ("https://securelist.com/tr/", "a.c-card__link[href*='/tr/']"),
    "Securelist RU TR": ("https://securelist.ru/tr/", "a.c-card__link[href*='/tr/']"),
    "Securelist": ("https://securelist.com/", "a.c-card__link"),
    "Securelist RU": ("https://securelist.ru/", "a.c-card__link"),
    "Kaspersky ICS CERT": (
        "https://ics-cert.kaspersky.com/publications/",
        "a.reports-list__item-title",
    ),
    "Derp Malware": ("https://www.derp.ca/malware/", "a[href*='/research/']"),
    "Derp Research": ("https://www.derp.ca/research/", "a[href*='/research/']"),
    # APT 列表有、无可用 RSS 的博客首页
    "LevelBlue": ("https://www.levelblue.com/blogs/spiderlabs-blog/", "a[href*='/blogs/']"),
    "Validin": ("https://www.validin.com/blog/", "a[href*='/blog/']"),
    "Intezer": ("https://intezer.com/blog/", "a[href*='/blog/']"),
    # 无 RSS（/feed 404），列表页服务端直出
    "CyberXtron": ("https://cyberxtron.com/resources/blogs", "a[href*='/resources/blogs/']"),
    # --- 用户第三批（2026-10）：RSS 不全或没有 RSS，补列表页 ---
    # RSS 只给 10 条且混营销文，分析栏目页更干净
    "AnyRun": (
        "https://any.run/cybersecurity-blog/category/malware-analysis/",
        r"regex:https://any\.run/cybersecurity-blog/(?!research/|write-for-us/|category/|tag/|author/|page/|comments/|feed/|wp-)[a-z0-9-]{8,}/",
    ),
    # 首页只挂 4 篇，/reports/ 是全量列表；结构化 IOC 仍由 hunters_ledger_crawler 负责
    "Hunter's Ledger": ("https://the-hunters-ledger.com/reports/", "a[href^='/reports/']"),
    "Deception.Pro": ("https://blog.deception.pro/blog/", "a[href^='/blog/']:not([href*='deceptionpro-'])"),
    # /us/rss.xml 基本全是公司新闻，threat-insight 栏目页只直出最新 3 篇
    "Proofpoint Threat Insight": (
        "https://www.proofpoint.com/us/blog/threat-insight",
        "a[href*='/us/blog/threat-insight/']",
    ),
    # 无 RSS（/feed/ 500）
    "Cyberint Dark Web": (
        "https://cyberint.com/blog/dark-web/",
        r"regex:https://cyberint\.com/blog/dark-web/(?!page/)[a-z0-9-]{8,}/",
    ),
    "Cyberint Research": (
        "https://cyberint.com/blog/research/",
        r"regex:https://cyberint\.com/blog/research/(?!page/)[a-z0-9-]{8,}/",
    ),
    # /blog/feed/ 404、/feed/ 是空 RSS；Threat Research 栏目才是带 IOC 的分析文
    "Morphisec": (
        "https://www.morphisec.com/blog/category/threat-research/",
        r"regex:https://www\.morphisec\.com/blog/(?!category/|page/|author/|tag/|feed/)[a-z0-9-]{12,}/",
    ),
    # 以下几家 RSS 失效（404 / 空 feed / 返回网页），改扫博客首页；链接可能是相对路径
    "Anomali": ("https://www.anomali.com/blog", r"regex:(?:https://www\.anomali\.com)?/blog/(?!category/|page/|tag/)[a-z0-9-]{12,}"),
    "SecurityLabs Datadog": (
        "https://securitylabs.datadoghq.com/",
        r"regex:(?:https://securitylabs\.datadoghq\.com)?/articles/[a-z0-9-]{8,}/?",
    ),
    "Securonix": ("https://www.securonix.com/blog/", r"regex:(?:https://www\.securonix\.com)?/blog/(?!category/|page/|tag/)[a-z0-9-]{12,}/?"),
    "Google Identity Security": (
        "https://cloud.google.com/blog/products/identity-security",
        r"regex:(?:https://cloud\.google\.com)?/blog/products/identity-security/[a-z0-9-]{12,}",
    ),
    # SecRSS 的 /feed 已 404；病毒木马栏目多是 CNCERT 银狐专项 / 僵尸网络通报，正文直接列 IOC
    "SecRSS 病毒木马": (
        "https://www.secrss.com/articles?tag=%E7%97%85%E6%AF%92%E6%9C%A8%E9%A9%AC",
        r"regex:https://www\.secrss\.com/articles/\d+",
    ),
    # --- 用户第四批（2026-10）---
    # 威胁研究在 /threat-command/ 下，/blog/ 多是产品文
    "Elastic Security Labs": (
        "https://www.elastic.co/security-labs/threat-command",
        r"regex:/security-labs/threat-command/(?!category/)[a-z0-9-]{12,}",
    ),
    # feedblitz RSS 停在 2026-02；首页链接是相对路径 /年/月/编号-slug
    "G DATA": (
        "https://blog.gdatasoftware.com/",
        r"regex:/20\d\d/\d\d/\d{4,6}-[a-z0-9-]+",
    ),
    # /hub/blog/rss 混着 DLP、Windows 运维文，威胁情报栏目更干净
    "Truesec": (
        "https://www.truesec.com/hub/blog/category/threat-intelligence",
        r"regex:https://www\.truesec\.com/hub/blog/(?!page/|category/)[a-z0-9-]{12,}",
    ),
}

# ============================================================
# 高优先级Feed（含IOC概率高）
# ============================================================
PRIORITY_FEEDS = {
    "The Hacker News", "Krebs on Security", "BleepingComputer",
    "Cisco Talos",
    "Security Affairs", "Dark Reading", "SecurityWeek",
    "AnyRun", "ASEC AhnLab", "OpenSource Malware", "Infostealers",
    "Securelist", "Securelist RU", "Securelist TR", "Securelist RU TR",
    "Kaspersky ICS CERT",
    "BreakGlass Intel", "Malwarebytes", "Hunt.io", "Cyble",
    "Recorded Future", "Unit 42", "CheckPoint Research",
    "Volexity", "Rapid7", "CrowdStrike", "SentinelOne", "SentinelOne Labs",
    "Elastic Security", "SANS ISC", "Flare.io",
    "SlowMist", "OSINT Team", "InfoSec Writeups",
    "Arctic Wolf", "HackRead", "Qianxin XLab", "D3Lab",
    "Seqrite",
    "Sophos X-Ops", "Cisco Security",
    "Help Net Security", "Graham Cluley",
    "Qianxin TI",
    "Codea Intel", "Dark Atlas", "Hybrid Analysis", "StealthMole", "Rewterz", "Socket.dev",
    "Epiphany Consulting", "Luke Acha", "DMpDump", "InTheCyber", "Qurium", "IIJ SEC", "Aikido",
    "Bfore AI", "Ox Security", "Silentpush", "DomainTools",

    # === APT CSV 新发现源（2026-07）===
    "Fox-IT", "RedAsgard", "Sonatype", "微步在线",
    "SafeDep", "PolySwarm", "KM Sec", "CyberXtron",

    # === JPCERT（2026-07）===
    "JPCERT/CC",

    # === ThreatNexus 补充源（2026-07）===
    "Google TAG", "Mandiant", "Google TI (Feedburner)", "Google Identity Security",
    "IBM X-Force", "IronScales",
    "The Record", "Wiz Research", "CISA Advisories",
    "CISA News", "NCSC UK", "Expel",
    "ThreatCluster",
    "Hunter's Ledger",
    "Derp Malware", "Derp Research",
    "Huntress", "LevelBlue SpiderLabs", "Field Effect",
    "Avertium", "K7 Labs", "DenWP", "SecurityScorecard",
    "LevelBlue", "Validin", "Intezer",
    "Morphisec", "SecRSS 病毒木马", "SecurityLabs Datadog", "Securonix",
    "Deception.Pro", "Proofpoint Threat Insight", "Cyberint Dark Web", "Cyberint Research",
}

# ============================================================
# 威胁情报关键词
# ============================================================
THREAT_ACTORS = [
    # === 国家级APT（朝鲜） ===
    "Lazarus", "APT38", "BlueNoroff", "TA444", "APT12",
    "North Korean", "DPRK", "Kimsuky", "Thallium", "APT37",
    "Sapphire Sleet", "Andariel", "Bluenoroff",
    # === 国家级APT（俄罗斯） ===
    "APT28", "Fancy Bear", "APT29", "Cozy Bear", "Sandworm",
    "Turla", "Gamaredon", "UNC1151", "UNC2452",
    "Nobelium", "Midnight Blizzard",
    "Star Blizzard", "Callisto Group", "Seaborgium",
    # === 国家级APT（中国） ===
    "APT33", "APT34", "OilRig", "APT35", "Phosphorus",
    "APT40", "APT41", "Mustang Panda", "HAFNIUM",
    "UNC5174", "UNC5325",
    # === 国家级APT（其他） ===
    "MuddyWater", "Seedworm", "APT39",
    "APT32", "OceanLotus",
    "DarkHotel", "Chollima",
    # === 网络犯罪团伙 ===
    "FIN7", "Carbanak", "Wizard Spider",
    "Contagious Interview", "DreamJob",
    "BlackCat", "ALPHV", "LockBit", "Black Basta",
    "Akira", "BianLian", "Play ransomware", "Qilin", "CLOP", "Snatch",
    "Scattered Spider", "0ktapus",
    "RansomHub", "Space Bears", "Hunters International",
    "INC Ransom", "Lynx Ransom",
    # === 已知恶意攻击者代号 ===
    "Silver Fox", "Raspberry Robin",
    "Flax Typhoon", "Volt Typhoon", "Salt Typhoon",
    "Void Arachne",
    "Dropping Elephant", "Void Balaur",
    "ToddyCat", "Armored Likho",
    "Funnull", "Mr_Rot13", "AllSyDevs",
    "TA444", "TA547",
    "RomCom", "Vice Society", "Rhysida",
    "CoralRaider", "Red Stinger",
    # === 常见别名 ===
    "ValleyRat", "WINOS", "OtterCookie", "PolyLangGhost",
    "Operation Blacksmith",
    # === 情报共享代号 ===
    "UTG-Q-1000", "UTG-Q-1015",
    # === 用户补充（2026-07）===
    "APT-C-60", "MalKamak", "Cyber Av3ngers", "RansomHouse",
    "Rhantus", "GoldFactory", "CUBA", "BlueBottle",
    "UNC6671", "MageCart", "The Gentlemen", "Warlock Group",
    "Smishing Triad", "INTERLOCK", "TeamTNT",
    "Operation C-Major", "Rare Werewolf", "GHOST STADIUM",
    "Shai-Hulud", "hackerbot-claw", "TeamPCP", "UTA0218",
    "Kairos", "HAZY TIGER", "QUILTED TIGER", "APT17",
    "RIDDLE SPIDER", "CryptoCore", "Mysterious Elephant",
    "Conti", "ShinyHunters", "UAC-0226", "Earth Lamia",
    "DarkSpectre", "Ghostwriter", "RAZOR TIGER", "Blacksuit",
    "WageMole", "UAC-0184", "The Shadow Brokers",
    "hightower6eu", "COOKIE SPIDER", "Earth Lusca",
    "APT-C-36", "Payouts King", "INJ3CTOR3", "Ink Dragon",
    "ShadowSyndicate", "8BASE", "Cloud Atlas", "UAT-8302",
    "JINX-0164", "Silent Ransom Group", "MOONLIGHT TIGER",
    "CL-CRI-1089", "Handala", "UNC6353", "GrayCharlie",
    "GOLD PRELUDE", "Paper Werewolf", "DragonForce",
    "SHADOW-WATER-063", "TA582", "LenAI", "DagonLocker",
    "Earth Krahang", "KongTuke", "Tortoiseshell", "GlassWorm",
    "Pink Sandstorm", "Webworm", "Storm-2755", "Vect",
    "IntelBroker", "OUTLAW SPIDER", "Earth Baxia",
    "GoldenEyeDog", "CylindricalCanine", "CuboidalCanine", "Atlas Lion",
    "Head Mare", "HeadMare",
]

MALWARE_NAMES = [
    # === 木马/后门 ===
    "Remcos", "AsyncRAT", "QuasarRAT", "Gh0stRAT",
    "PlugX", "ShadowPad",
    "Silver", "Sliver", "Brute Ratel", "Covenant",
    "Mythic", "DeimosC2", "Nighthawk",
    "ValleyRat", "WINOS", "OtterCookie", "PolyLangGhost",
    "MagicRat", "QuiteRat", "QuietRat",
    "CollectionRat", "RemotePE",
    "KandyKorn", "RustBucket", "Mach-O Man",
    "RustDuck", "MODBEACON", "BusySnake",
    "GigaWiper", "AryStinger",
    "Needle",
    "XCTDoor", "Metakit", "FireAnt",
    "Mastra", "RustyAttr", "MATA", "Volgmer",
    "HyperShell", "MythicAgent",
    # === 窃密木马 ===
    "Vidar", "Stealc", "RedLine", "Raccoon",
    "Lumma", "LummaC2", "RisePro", "Meduza",
    "HiddenRisk",
    "OpenClaw", "Anti-bot",
    # === 加载器/投放器 ===
    "ClickFix", "SocGholish", "ClearFake",
    "DarkGate", "RedTail", "Marstech1",
    "SNOWLIGHT", "GGBOND",
    "SynkLoader", "InstallFix", "ManualFinder", "BaoLoader",
    # === 僵尸网络 ===
    "RustDuck", "Netdragon", "Kimwolf",
    # === C2框架 ===
    "Cobalt Strike", "Havoc", "Brute Ratel",
    "Sliver", "Mythic", "DeimosC2", "Nighthawk",
    "NimPlant", "PoshC2",
    # === 勒索软件 ===
    "LockBit", "Black Basta", "BlackCat", "ALPHV",
    "Akira", "BianLian", "Play ransomware", "Qilin", "CLOP", "Snatch",
    "RansomHub", "INC Ransom", "Rhysida",
    "Medusa", "Lynx Ransom",
    # === 信息窃取器 ===
    "SwimSnake",
    # === 特定后门 ===
    "RedPeanut", "HenBox",
    "Anti-bot", "OpenClaw",
    "AI-driven malware",
    # 不收录通用分类词（backdoor/trojan/loader 等会命中几乎每篇文章）
    # === 用户补充C2/工具（2026-07）===
    "Keitaro", "Mozi", "Tactical RMM", "Vshell",
    "Mirai", "Gophish", "Interactsh",
    "Burp Collaborator", "Ramnit", "Hajime",
    "CyberStrikeAI", "Metasploit", "Supershell",
    "AdaptixC2", "Java Chains", "Nessus VA", "Prism X",
    "Yakit Security Tool", "reNgine", "ReverseSSH",
    "Viper", "Burp Suite", "Ligolo-ng", "DcRat", "XenoRAT",
    "Pyramid C2", "evilgophish", "KeyPlug", "Starkiller",
    "DNSLog", "X-Ray Vuln Scanner", "MITRE Caldera",
    "Unam", "Setcode RAT", "Hak5 Cloud C2", "Moobot",
    "GobRAT", "DarkComet", "Albiriox", "VenomRAT", "DayBreak",
    "OWASP ZAP API", "Chaos RAT", "SpiceRAT",
    "Kaiji", "Responder", "SectopRAT", "HOOKBOT",
    "RedJuliett", "Daam", "Pupy C2", "XploitSPY",
    "Gafgyt", "RedWarden", "SparkRAT", "Nosviak4",
    "Pantegana RAT", "Amadey", "JS-Tap", "Nemo",
    "TuoniC2", "LightSpy", "Chalubo RAT",
    "CloudSorcerer", "Tsundere Botnet",
    "UltraVNC", "BlueShell Backdoor", "Zshell", "L3MON",
    "Xillen Stealer", "njRAT", "Orcus RAT", "S500 RAT",
    "BYOB", "Odyssey", "SHub Stealer", "Silver RAT",
    "Gozi", "BitRAT", "BOFAMET", "Ares", "AZORult",
    "RAPTOR RAT", "Scarface Stealer",
    "Octopus", "VoidLink C2", "Nebula Stealer",
    "ClayRat", "SpyAgent", "RedGuard", "ZeroTrace",
    "Ermac", "DoomedLoader", "Lokibot",
    "PhantomCore", "PhantomGraph",
]

# === 扩充：从 malpedia.bib 集成关键词 ===
MALPEDIA_EXTRA = load_malpedia_keywords(min_count=3)
if MALPEDIA_EXTRA:
    # 分类合并到 THREAT_ACTORS 和 MALWARE_NAMES
    THREAT_ACTORS.extend(MALPEDIA_EXTRA[:200])
    MALWARE_NAMES.extend(MALPEDIA_EXTRA[:200])
    # 去重
    THREAT_ACTORS = sorted(set(THREAT_ACTORS), key=lambda x: x)
    MALWARE_NAMES = sorted(set(MALWARE_NAMES), key=lambda x: x)
    print(f"  [malpedia集成] THREAT_ACTORS 扩充到 {len(THREAT_ACTORS)} 个")
    print(f"  [malpedia集成] MALWARE_NAMES 扩充到 {len(MALWARE_NAMES)} 个")

# 网络 IOC 正则已集中到 crawler_utils.extract_iocs（含半去括号 / hxxp）

EXCLUDE_DOMAINS = set([
    # === 主流合法服务 ===
    "google.com", "facebook.com", "twitter.com", "x.com", "gmail.com",
    "microsoft.com", "apple.com", "amazon.com", "linkedin.com",
    "youtube.com", "instagram.com", "reddit.com", "blogspot.com",
    "medium.com", "github.com", "gitlab.com", "bitbucket.org",
    "thehackernews.com", "bleepingcomputer.com", "krebsonsecurity.com",
    "welivesecurity.com", "sentinelone.com", "crowdstrike.com",
    "elastic.co", "unit42.paloaltonetworks.com", "rapid7.com",
    "checkpoint.com", "any.run", "jfrog.com", "ahnlab.com",
    "cloudflare.com", "trycloudflare.com",
    "t.co", "bit.ly", "tinyurl.com", "ow.ly", "buff.ly",
    "torproject.org", "wikipedia.org", "abuse.ch",
    "npmjs.com", "npm.org", "pypi.org", "nuget.org",
    "docker.com", "docker.io", "duckdns.org",
    "pastebin.com", "raw.githubusercontent.com",
    "telegram.me", "t.me", "steamcommunity.com",
    "claude.ai", "chatgpt.com", "openai.com",
    "crates.io", "rubygems.org", "packagist.org",
    "nextjs.org", "js.org", "qq.com", "tenderly.co",
    "intel.breakglass.tech", "breakglass.tech",
    "deception.pro", "the-hunters-ledger.com", "group-ib.com",
    "proofpoint.com", "emergingthreats.net", "cyberint.com", "hunt.io",
    "gdatasoftware.com", "truesec.com", "huntress.com", "databreaches.net",
    "kubernetes.io", "microsoftonline.com",
    "cnbc.com", "msn.com", "arstechnica.com", "reuters.com", "bloomberg.com",
    "theregister.com", "therecord.media", "windowsforum.com",
    "safedep.io", "ghcr.io", "ctlogs.dev", "morphisec.com",

    # === 代码托管/部署平台 ===
    "vercel.app", "onrender.com", "netlify.app", "pages.dev",
    "fly.dev", "azurewebsites.net", "herokuapp.com",
    "railway.app", "cyclic.app", "replit.app",
    "github.io", "gitlab.io", "bitbucket.io",

    # === 区块链浏览器（可能被恶意使用，但更多是误报） ===
    "etherscan.io", "bscscan.com", "polygonscan.com",
    "tronscan.org", "mempool.space", "dogechain.info",
    "blockchair.com", "litescan.io", "solscan.io",
    "btc.com", "blockchain.com", "blockchain.info",

    # === 域名注册商/DNS ===
    "sectigo.com", "schema.org", "gname.com",
    "dynv6.net", "kro.kr", "npoint.io",
    "fifa.com", "booking.com", "shutterstock.com",
    "foundryco.com", "googledomains.com", "globaldomaingroup.com",
    "hetzner.com", "ovh.net", "hetzner",

    # === URL缩短 ===
    "short.gy", "shorturl.at", "tiny.cc", "short.link",

    # === 云存储/CDN 基础设施（单独出现时是平台域名，不是 IOC） ===
    "windows.net", "core.windows.net", "blob.core.windows.net",
    "amazonaws.com", "s3.amazonaws.com", "cloudfront.net",
    "googleapis.com", "googleusercontent.com", "appspot.com",
    "akamaihd.net", "akamaized.net", "fastly.net", "jsdelivr.net",
    "unpkg.com", "cdnjs.com", "bootstrapcdn.com",
    "sharepoint.com", "onedrive.live.com", "office.com",
    "mailchannels.net", "sendgrid.net", "clarity.microsoft.com",
])

EXCLUDE_DOMAIN_PATTERNS = [
    # === 文件扩展名 ===
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".py", ".pyc", ".pyo", ".go", ".rs", ".java", ".class",
    ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".vbs",
    ".ahk", ".mui", ".manifest", ".pak", ".dat",
    ".md", ".txt", ".json", ".xml", ".csv", ".yaml", ".yml",
    ".cfg", ".conf", ".ini", ".log", ".toml",
    ".dll", ".exe", ".sys", ".so", ".dylib", ".wasm",
    ".aspx", ".jsp", ".php", ".asp", ".ashx", ".war",
    ".png", ".jpg", ".gif", ".svg", ".ico", ".webp",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".pdb", ".pdf", ".docx", ".xlsx", ".lnk", ".cpl",
    ".lock", ".sum", ".mod", ".ltd",
    ".ac.uk", ".gov.uk", ".nhs.uk", ".police.uk",
    ".edu", ".ac.kr", ".edu.cn", ".ac.cn",
    "ac.uk", "gov.uk", "nhs.uk",

    # === JS/TS 属性访问 ===
    ".length", ".toString", ".valueOf", ".name", ".type",
    ".call(", ".apply(", ".bind(",
    ".prototype", ".constructor",
    ".map(", ".filter(", ".reduce(", ".forEach",
    ".then(", ".catch(", ".finally(",
    ".push(", ".pop(", ".shift(", ".unshift",
    ".split(", ".join(", ".concat(",
    ".indexOf", ".includes", ".startsWith", ".endsWith",

    # === Node.js / JavaScript API ===
    "node.", "node.js", "Node.", "Node.js",
    "index.", "main.", "app.", "config.",
    "path.", "fs.", "os.", "process.", "buffer.", "stream.",
    "require.", "module.", "exports.", "import.",
    "console.", "settimeout", "setinterval",
    "string.", "number.", "array.", "object.", "date.", "math.",
    "json.", "regexp.", "promise.", "error.", "typeerror.",
    "function.", "class.", "this.", "prototype.",
    "crypto.", "subtlecrypto.", "webcrypto.",
    "fetch(", "await ", "async ",
    "socket.", "io.", "http.", "https.", "url.", "querystring.",
    "child_process", "exec(", "spawn(",
    "navigator.", "document.", "window.", "location.",
    "localstorage", "sessionstorage",

    # === Python API ===
    "sqlite3.", "win32crypt.", "ctypes.",
    "base64.", "hashlib.", "hmac.",
    "itertools.", "collections.", "functools.",
    "threading.", "multiprocessing.",
    "subprocess.", "shutil.", "tempfile.",
    "argparse.", "logging.", "traceback.",
    "django.", "flask.", "fastapi.",
    "numpy.", "pandas.", "tensorflow.", "torch.",
    "selenium.", "requests.", "beautifulsoup.", "scrapy.",

    # === .NET / C# / CLR ===
    "system.", "microsoft.", "windows.",
    "shell.", "wscript.", "appdomain.",
    "reflection.", "runtime.", "interopservices.",
    "componentmodel.", "configuration.",
    "security.cryptography", "security.cryptography",
    "diagnostics.", "management.",
    "linq.", "collections.generic",
    "text.regularexpressions", "text.stringbuilder",
    "threading.tasks", "threading.thread",
    "net.sockets", "net.mail",

    # === Go ===
    "golang.", "google.golang", "gopkg.",
    "fmt.", "net.", "http.", "grpc.",
    "proto.", "bufio.", "strings.", "strconv.",
    "encoding.", "decoding.", "json.", "xml.", "yaml.",

    # === Rust ===
    "std::", "crate::", "self::", "super::",
    "rustc_", "rust_",

    # === 框架/库名 ===
    "vue.js", "react.js", "next.js", "angular.",
    "jquery.", "bootstrap.", "tailwind.",
    "express.", "koa.", "socket.io",
    "tensorflow", "pytorch",

    # === Windows 内部 ===
    "macos.", "macOS.", "windows.", "linux.", "android.", "ios.",
    "event.", "host.", "user.", "api.",
    "logging.", "backdoor.", "trojan.", "worm.", "rootkit.",
    "registry.", "services.", "drivers.", "printers.",

    # === 环境变量/占位符 ===
    "%userprofile%", "%appdata%", "%temp%",
    "[c2]", "{c2}", "$c2",
    "example.com", "test.com", "domain.com",
    "yourdomain", "your-server",

    # === 通用变量名 ===
    "editor.", "agent.", "context.", "runtime.",
    "runner.", "loader.", "builder.",
    "callback", "handler", "middleware",
    "config.", "setting.", "default.",
    "src.", "dist.", "build.", "lib.", "util.",
    "temp.", "tmp.", "cache.", "data.",
    # === 加密项目/其他 ===
    "coredao", "coredao.",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.7",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}

session = requests.Session()
session.headers.update(HEADERS)


# ============================================================
# 状态管理
# ============================================================
def load_state():
    state = {"seen_urls": {}, "last_check": None, "total_discovered": 0}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
        except (OSError, ValueError):
            return state
    return _migrate_state_keys(state)


def _migrate_state_keys(state):
    """
    把历史上按 md5(url|title) 存的指纹重建为 url_fingerprint(url)。

    老 key 混用了 title 和 source 作为第二段，同一篇文章存在多个 key，
    重建后同一 URL 只保留一条（取最早的 seen_at，保持"首次见到"语义）。
    """
    seen = state.get("seen_urls") or {}
    rebuilt = {}
    for meta in seen.values():
        if not isinstance(meta, dict):
            continue
        url = meta.get("url")
        if not url:
            continue
        fp = get_article_fingerprint(url)
        prev = rebuilt.get(fp)
        if prev is None or meta.get("seen_at", "") < prev.get("seen_at", ""):
            rebuilt[fp] = meta
    state["seen_urls"] = rebuilt
    return state


def save_state(state):
    state["last_check"] = datetime.now().isoformat()
    seen = state.get("seen_urls", {})
    if len(seen) > MAX_SEEN_URLS:
        sorted_urls = sorted(seen.items(), key=lambda x: x[1].get("seen_at", ""), reverse=True)
        state["seen_urls"] = dict(sorted_urls[:MAX_SEEN_URLS])
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def _parse_published(value):
    """RSS 的 RFC 822 或 Atom / meta 的 ISO 8601，统一成 UTC 时间；解析不了返回 None。"""
    s = (value or "").strip()
    if not s:
        return None
    dt = None
    try:
        dt = parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError):
        dt = None
    if dt is None:
        iso = s.replace("Z", "+00:00")
        if re.match(r"^\d{4}-\d{2}-\d{2}T", iso):
            iso = re.sub(r"\.\d+", "", iso)
        try:
            dt = datetime.fromisoformat(iso[:25])
        except ValueError:
            m = re.match(r"^(\d{4}-\d{2}-\d{2})", s)
            if m:
                dt = datetime.fromisoformat(m.group(1))
            else:
                for fmt in ("%b %d, %Y", "%B %d, %Y", "%b %d %Y", "%B %d %Y"):
                    try:
                        dt = datetime.strptime(s.replace(".", ""), fmt)
                        break
                    except ValueError:
                        continue
                if dt is None:
                    return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _is_too_old(published):
    if not MAX_ARTICLE_AGE_DAYS:
        return False
    dt = _parse_published(published)
    if dt is None:
        return False
    return dt < datetime.now(timezone.utc) - timedelta(days=MAX_ARTICLE_AGE_DAYS)


_PUBLISHED_META = (
    ("meta", {"property": "article:published_time"}),
    ("meta", {"name": "article:published_time"}),
    ("meta", {"itemprop": "datePublished"}),
    ("meta", {"name": "date"}),
    ("meta", {"name": "pubdate"}),
    ("meta", {"name": "publishdate"}),
    ("meta", {"property": "og:published_time"}),
)


# 页面没有 meta / time 标签、只在 "Published On  Oct 08, 2026" 这种文字里写日期的站点。
# 必须锚定标签文字：正文里常有 "Since August 16, 2023" 这类历史日期。
PAGE_DATE_TEXT_HOSTS = {"cyberxtron.com"}
_TEXT_DATE_RE = re.compile(
    r"Published On\s+"
    r"((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? \d{1,2},? \d{4})\b"
)


def _page_published(soup, raw, url=""):
    for tag, attrs in _PUBLISHED_META:
        el = soup.find(tag, attrs=attrs)
        if el and el.get("content"):
            return el["content"].strip()
    m = re.search(r'"datePublished"\s*:\s*"([^"]+)"', raw)
    if m:
        return m.group(1)
    el = soup.find("time", attrs={"datetime": True})
    if el:
        return el["datetime"].strip()
    host = urlparse(url).netloc.lower().replace("www.", "")
    if host in PAGE_DATE_TEXT_HOSTS:
        m = _TEXT_DATE_RE.search(soup.get_text(" ", strip=True))
        if m:
            return m.group(1)
    return ""


def _remember_seen(seen, article, source=None):
    url = article.get("url", "")
    if not url:
        return
    seen[get_article_fingerprint(url)] = {
        "url": url,
        "title": article.get("title", ""),
        "source": source or article.get("source", ""),
        "published": article.get("published", ""),
        "seen_at": datetime.now().isoformat(),
    }


def get_article_fingerprint(url, title=None):
    """
    文章指纹只取 URL。

    标题参与哈希会导致同一篇文章在两条发现路径下产生不同指纹：
    RSS 路径传真实标题，博客首页路径传站点名 —— 于是每轮都重复下载。
    title 参数仅为兼容旧调用保留，不参与计算。
    """
    return url_fingerprint(url)


def _skip_article_url(url):
    low = (url or "").lower()
    return any(x in low for x in SKIP_ARTICLE_URL_SUBSTR)


# ============================================================
# RSS Feed解析
# ============================================================
_ATOM_NS = "{http://www.w3.org/2005/Atom}"
_DC_NS = "{http://purl.org/dc/elements/1.1/}"


def _local_name(tag):
    tag = tag or ""
    return tag.rsplit("}", 1)[-1]


def _child(parent, local):
    local = (local or "").split(":")[-1]
    for child in list(parent):
        if _local_name(child.tag) == local:
            return child
    return None


def _get_text(parent, xpath):
    try:
        local = str(xpath).split(":")[-1]
        el = _child(parent, local)
        if el is None and xpath == "dc:date":
            el = parent.find(_DC_NS + "date")
        if el is None:
            return ""
        if el.text and el.text.strip():
            return el.text.strip()
        return "".join(el.itertext()).strip()
    except Exception:
        return ""


def _elem_link(el):
    child = _child(el, "link")
    if child is None:
        return ""
    href = (child.get("href") or "").strip()
    if href:
        return href
    return (child.text or "").strip()


def _atom_entries(root):
    out = [e for e in root.iter() if _local_name(e.tag) == "entry"]
    return out


def _atom_link(entry):
    links = [c for c in list(entry) if _local_name(c.tag) == "link"]
    fallback = ""
    html = ""
    for el in links:
        href = (el.get("href") or "").strip()
        if not href:
            continue
        if not fallback:
            fallback = href
        rel = (el.get("rel") or "alternate").lower()
        typ = (el.get("type") or "").lower()
        if rel == "alternate" and (not typ or "html" in typ or "xhtml" in typ):
            return href
        if rel == "alternate" and not html:
            html = href
    return html or fallback


def _iter_rss_items(root):
    return [e for e in root.iter() if _local_name(e.tag) == "item"]


_XML_CTRL_RE = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_XML_BARE_AMP_RE = re.compile(rb"&(?!(?:[a-zA-Z][a-zA-Z0-9]*|#\d+|#x[0-9a-fA-F]+);)")
_XML_NAMED_ENT_RE = re.compile(rb"&([a-zA-Z][a-zA-Z0-9]*);")
_XML_ENTITIES = {b"amp", b"lt", b"gt", b"quot", b"apos"}


def _clean_xml(raw):
    """很多站的 RSS 不规范（开头空行、控制字符、裸 &、&nbsp; 等 HTML 实体），ET 一报错整份就丢了。"""
    import html.entities
    s = raw.lstrip()
    s = _XML_CTRL_RE.sub(b"", s)
    s = _XML_BARE_AMP_RE.sub(b"&amp;", s)

    def _ent(m):
        name = m.group(1)
        if name in _XML_ENTITIES:
            return m.group(0)
        cp = html.entities.name2codepoint.get(name.decode("ascii", "ignore"))
        return "&#{};".format(cp).encode() if cp else b"&amp;" + name + b";"
    return _XML_NAMED_ENT_RE.sub(_ent, s)


def _regex_feed_items(text):
    """XML 清理后仍解析失败时的兜底：逐个 <item> 用正则取字段。"""
    def field(block, tag):
        m = re.search(r"<{0}[^>]*>(.*?)</{0}>".format(tag), block, re.S | re.I)
        if not m:
            return ""
        v = m.group(1).strip()
        v = re.sub(r"^<!\[CDATA\[(.*)\]\]>$", r"\1", v, flags=re.S)
        return re.sub(r"<[^>]+>", " ", v).strip()
    out = []
    for block in re.findall(r"<item[\s>].*?</item>", text, re.S | re.I):
        a = {
            "title": field(block, "title"),
            "url": field(block, "link") or field(block, "guid"),
            "published": field(block, "pubDate") or field(block, "dc:date"),
            "summary": field(block, "description")[:2000],
        }
        if a["url"].startswith("http") and a["title"]:
            out.append(a)
    return out


def _get_with_retry(url, timeout=20):
    """走代理时偶发 TLS 握手被断 / 连接重置，重试一次基本就能过。"""
    for attempt in range(2):
        try:
            return session.get(url, timeout=timeout)
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
            if attempt:
                raise
            time.sleep(2)


def fetch_feed(url):
    try:
        r = _get_with_retry(url)
        r.raise_for_status()
        content = r.content.decode(r.encoding or "utf-8", "replace")
        head = content[:800].lower()
        articles = []
        try:
            root = ET.fromstring(r.content)
        except ET.ParseError:
            try:
                root = ET.fromstring(_clean_xml(r.content))
            except ET.ParseError:
                return _regex_feed_items(content)

        if "<feed" in head or _local_name(root.tag) == "feed":
            for entry in _atom_entries(root):
                link = _atom_link(entry) or _get_text(entry, "id")
                a = {
                    "title": _get_text(entry, "title"),
                    "url": link,
                    "published": _get_text(entry, "published") or _get_text(entry, "updated"),
                    "summary": _get_text(entry, "summary") or _get_text(entry, "content") or "",
                }
                if a["url"] and a["title"] and a["url"] != a["title"]:
                    articles.append(a)
            return articles

        for item in _iter_rss_items(root):
            a = {
                "title": _get_text(item, "title"),
                "url": _elem_link(item),
                "published": _get_text(item, "pubDate") or _get_text(item, "dc:date"),
                "summary": _get_text(item, "description") or _get_text(item, "encoded") or "",
            }
            if a["url"] and a["title"]:
                articles.append(a)
        return articles
    except Exception:
        return []


# ============================================================
# 威胁情报文章评分（用于预筛选，避免下载噪音）
# ============================================================
THREAT_INTEL_TITLE_KEYWORDS = [
    "C2", "C&C", "command and control", "botnet", "C2 server",
    "IOC", "indicator of compromise", "SHA256", "YARA",
    "malware", "trojan", "backdoor", "RAT", "loader", "dropper",
    "phishing", "zero-day", "0-day", "zero day",
    "ransomware", "supply chain",
    "APT", "threat actor", "threat group",
    "shellcode",
    "DLL sideloading", "process injection", "privilege escalation",
    "ClickOnce",
    "Sliver", "Cobalt Strike", "Brute Ratel", "Mythic",
    "UNC", "STOCKSTAY", "Turla", "malware family",
]

# 太泛，只打标题，避免摘要模板里的 analysis/exploit 把新闻稿刷到阈值以上
GENERIC_TITLE_KEYWORDS = [
    "exploit", "exploitation", "campaign", "analysis", "detection",
    "hunting", "compromise", "intrusion", "payload", "malicious",
    "persistence", "breach", "hash", "MD5", "indicator",
    "proxy", "tunnel", "redirector",
]

NOISE_TITLE_KEYWORDS = [
    "webinar", "podcast", "announce", "release notes",
    "appoints", "promotes", "named", "award", "partner",
    "earnings", "survey", "report: ", "state of ",
    "introducing", "welcome", "congratulations",
    "save the date", "registration",
    "now available", "labor day", "black friday", "% off",
]

_PROMO_RE = re.compile(
    r"\$\d|\d%\s*off|for \$\d|labor day|black friday|cyber monday",
    re.I,
)


def score_article(article):
    """根据标题/摘要评估文章的情报价值分数"""
    title = (article.get("title") or "")
    summary = (article.get("summary") or "")
    blob = (title + " " + summary).lower()
    title_l = title.lower()
    score = 0

    # 优先源必须能过阈值（15），除非命中噪音词
    if article.get("source", "") in PRIORITY_FEEDS:
        score += 20

    for kw in THREAT_INTEL_TITLE_KEYWORDS:
        if kw.lower() in blob:
            score += 15

    for kw in GENERIC_TITLE_KEYWORDS:
        if kw.lower() in title_l:
            score += 12

    for actor in THREAT_ACTORS:
        if actor.lower() in blob:
            score += 20

    for mw in MALWARE_NAMES:
        if mw.lower() in blob:
            score += 15

    for kw in NOISE_TITLE_KEYWORDS:
        if kw.lower() in title_l:
            score -= 30

    if _PROMO_RE.search(title):
        score -= 40

    if len(title) < 15:
        score -= 10

    return score


# 只匹配整行就是一个 IOC 的情况（IOC 附录表格的典型形态）
_IOC_LINE_RE = re.compile(
    r"""^(?:
        (?:\d{1,3}(?:\s*\[?\s*\.\s*\]?\s*\d{1,3}){3})(?::\d{1,5})?   # IP / 括号化 IP
      | [a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}              # md5 / sha1 / sha256
      | (?:h(?:xx)?tps?|ftp)\s*\[?\s*:\s*\]?\s*//\S+                 # URL / defanged URL
      | (?:[a-zA-Z0-9-]+\s*\[?\s*\.\s*\]?\s*)+[a-zA-Z]{2,}           # 域名 / defanged 域名
    )$""",
    re.VERBOSE,
)

# 导航/页脚噪声。用词边界匹配，避免 "by " / "related" 之类子串误杀正文句子。
_NAV_RE = re.compile(
    r"\b(?:recent\s+posts?|related\s+(?:posts?|articles?|reading)|"
    r"categories|tags?\s*:|share\s*(?:this)?\s*:|"
    r"subscribe|newsletter|leave\s+a\s+(?:reply|comment)|"
    r"posted\s+(?:on|by)|read\s+more|follow\s+us|"
    r"copyright|all\s+rights\s+reserved|cookie\s+policy|privacy\s+policy)\b",
    re.IGNORECASE,
)


def _looks_like_ioc_line(line):
    """整行是否就是一条 IOC。这类行必须无条件保留。"""
    s = line.strip().strip("|").strip().rstrip(",;")
    if not s or len(s) > 2048:
        return False
    return bool(_IOC_LINE_RE.match(s))


def _strip_nav_lines(text):
    """
    去掉导航/页脚行，但绝不丢弃 IOC 行。

    旧实现按 len<15 / startswith("http") / 子串命中 nav 词 三条规则过滤，
    正好把 IOC 附录里"一行一个裸 IP/域名/URL"的内容全部删掉，
    导致长篇威胁报告提取不到任何 IOC。
    """
    kept = []
    for raw in text.split("\n"):
        line = raw.strip()
        if not line:
            continue
        if _looks_like_ioc_line(line):
            kept.append(line)
            continue
        if _NAV_RE.search(line):
            continue
        if len(line) < 15:
            continue
        kept.append(line)
    return "\n".join(kept) if kept else text


def download_article(url):
    try:
        r = session.get(url, timeout=30)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        published = _page_published(soup, r.text, url)

        # 清理干扰元素
        for sel in ["script", "style", "noscript", "iframe", "nav", "header", "footer",
                     ".sidebar", ".menu", ".nav", ".footer", ".comments", ".related-posts",
                     ".recommended", ".social-share", ".newsletter", ".subscribe"]:
            for tag in soup.select(sel):
                tag.decompose()

        # 提取标题
        title = ""
        t = soup.find("title")
        if t:
            title = t.get_text(strip=True)
            # 安全内参标题是 "…（六）- 安全内参"，分隔符前没有空格
            title = re.sub(r"\s*[-|–—]\s*安全内参\s*$", "", title)
            for sep in [" | ", " – ", " — ", " - "]:
                if sep in title:
                    title = title.split(sep)[0].strip()
                    break

        # 智能正文提取：优先找包含最多 <p> 标签的容器
        candidates = []
        # 尝试语义标签
        for sel in ["article", "[role='main']", "main", ".post-content", ".article-content",
                     ".entry-content", ".article-body", ".story-body", ".content"]:
            el = soup.select_one(sel)
            if el:
                p_count = len(el.find_all("p"))
                text_len = len(el.get_text(strip=True))
                if text_len > 500:
                    candidates.append((text_len, p_count, el))

        # 如果没有找到好的语义容器，找包含最多 <p> 的 div
        if not candidates:
            for div in soup.find_all("div"):
                p_count = len(div.find_all("p"))
                if p_count >= 3:
                    text_len = len(div.get_text(strip=True))
                    candidates.append((text_len, p_count, div))

        if candidates:
            # 取文本量最大的容器
            candidates.sort(key=lambda x: x[0], reverse=True)
            text = candidates[0][2].get_text(separator="\n", strip=True)
        else:
            # 兜底：取所有 <p> 标签文本
            paragraphs = soup.find_all("p")
            text = "\n".join(p.get_text(strip=True) for p in paragraphs if len(p.get_text(strip=True)) > 20)

        if not text or len(text) < 200:
            return None

        text = _strip_nav_lines(text)

        out = {
            "title": title or urlparse(url).path,
            "content": text[:MAX_CONTENT_CHARS],
            "content_length": len(text),
        }
        if published:
            out["page_published"] = published
        return out
    except Exception:
        return None


# ============================================================
# URL文章发现（补充无RSS博客）
# ============================================================
_SKIP_HOME_HOSTS = {
    "feeds.feedburner.com", "feedburner.com", "rss.app",
    "cloudblog.withgoogle.com",
}

# RSS 地址推不出博客首页时的手工覆盖
HOMEPAGE_OVERRIDES = {
    "Unit 42": "https://unit42.paloaltonetworks.com/",
    "Unit 42 (Native)": "https://unit42.paloaltonetworks.com/",
    "The Hacker News": "https://thehackernews.com/",
    "Google TI (Feedburner)": "https://cloud.google.com/blog/topics/threat-intelligence/",
    "Mandiant": "https://cloud.google.com/blog/topics/threat-intelligence/",
    "CrowdStrike": "https://www.crowdstrike.com/en-us/blog/",
    "Microsoft Security": "https://www.microsoft.com/en-us/security/blog/",
    "Fortinet": "https://www.fortinet.com/blog/threat-research",
    "Proofpoint": "https://www.proofpoint.com/us/blog/threat-insight",
    "CheckPoint Research": "https://research.checkpoint.com/",
    "Wiz Research": "https://www.wiz.io/blog/tag/research",
    "ThreatCluster": "https://threatcluster.io/",
    "ThreatCluster Dark Web": "https://threatcluster.io/dark-web",
    "ThreatCluster Vulns": "https://threatcluster.io/vulnerabilities",
    "ThreatCluster Exploits": "https://threatcluster.io/exploits",
    "Derp Malware": "https://www.derp.ca/malware/",
    "Derp Research": "https://www.derp.ca/research/",
}

_HOME_SKIP_PATH = (
    "/tag/", "/tags/", "/category/", "/categories/", "/author/", "/page/",
    "/feed", "/rss", "/login", "/about", "/contact", "/privacy", "/search",
    "/wp-json", "/cdn-cgi", "/cart", "/account", "/newsletter",
)


def _homepage_from_feed(name, feed_url):
    if name in HOMEPAGE_OVERRIDES:
        return HOMEPAGE_OVERRIDES[name]
    p = urlparse(feed_url)
    host = (p.netloc or "").lower()
    if host in _SKIP_HOME_HOSTS or host.endswith(".feedburner.com"):
        return None
    path = p.path.rstrip("/")
    for suffix in ("/feed", "/rss", "/atom.xml", "/rss.xml", "/feed.xml", "/feed/"):
        cut = suffix.rstrip("/")
        if path.endswith(cut):
            path = path[: -len(cut)]
            break
    if path.endswith(".xml") or path.endswith(".rss"):
        path = path.rsplit("/", 1)[0]
    return "{}://{}{}".format(p.scheme, p.netloc, path or "/")


def _looks_like_article(href, home_host):
    try:
        p = urlparse(href)
    except ValueError:
        return False
    host = (p.netloc or "").lower().replace("www.", "")
    home = (home_host or "").lower().replace("www.", "")
    if host and home and host != home and not host.endswith("." + home):
        return False
    path = (p.path or "").lower()
    if any(x in path for x in _HOME_SKIP_PATH):
        return False
    if len(path) < 16:
        return False
    if any(x in path for x in (
        "/blog/", "/research/", "/labs/", "/post/", "/posts/",
        "/articles/", "/article/", "/reports/", "/report/",
        "/intel/", "/threats/", "/malware/", "/cluster/",
    )):
        return True
    if re.search(r"/20\d{2}/", path):
        return True
    segs = [s for s in path.split("/") if s]
    return len(segs) >= 2 and "-" in segs[-1]


def _listing_hosts():
    hosts = set()
    for _name, (url, _sel) in BLOG_LISTINGS.items():
        hosts.add(urlparse(url).netloc.lower().replace("www.", ""))
    return hosts


def discover_priority_homepages(state, max_articles=12):
    """对有 RSS、但没单独配首页选择器的优先源，扫博客首页上的文章链接。"""
    seen = state.get("seen_urls", {})
    covered = _listing_hosts()
    found = []
    print("\n  --- 优先博客首页补扫 ---")
    for name, feed_url in sorted(RSS_FEEDS.items()):
        if name not in PRIORITY_FEEDS:
            continue
        if name in SKIP_HOMEPAGE_SCAN:
            continue
        home = _homepage_from_feed(name, feed_url)
        if not home:
            continue
        host = urlparse(home).netloc.lower().replace("www.", "")
        if host in covered:
            continue
        try:
            r = session.get(home, timeout=15)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            urls = []
            for a in soup.find_all("a", href=True):
                href = a.get("href", "")
                if href.startswith("/"):
                    parsed = urlparse(home)
                    href = "{}://{}{}".format(parsed.scheme, parsed.netloc, href)
                if not href.startswith("http") or len(href) < 36:
                    continue
                if any(x in href.lower() for x in ["/tag/", "/category/", "/author/", "/page/", "#"]):
                    continue
                if not _looks_like_article(href, host):
                    continue
                if _skip_article_url(href):
                    continue
                if href not in urls:
                    urls.append(href)
                if len(urls) >= max_articles:
                    break
            new_count = 0
            for u in urls:
                fp = get_article_fingerprint(u)
                if fp not in seen:
                    found.append({"source": name, "url": u})
                    new_count += 1
            if urls:
                print("    {:30s} {} 篇 (新{}篇)".format(name, len(urls), new_count))
                covered.add(host)
        except Exception as e:
            print("    {:30s} (!) {}".format(name, str(e)[:80]))
    print("    首页补扫新文章: {}".format(len(found)))
    return found


def discover_articles(state, max_articles=15):
    """从博客首页发现最新文章URL（带去重，支持CSS选择器和正则表达式）"""
    seen = state.get("seen_urls", {})
    print("\n  --- 从 {} 个博客首页发现文章 ---".format(len(BLOG_LISTINGS)))
    total = []
    for name, (url, selector) in sorted(BLOG_LISTINGS.items()):
        try:
            r = session.get(url, timeout=15)
            r.raise_for_status()
            raw = r.text

            # 判断是否为正则表达式模式
            if selector.startswith("regex:"):
                pattern = selector[6:]
                matched = re.findall(pattern, raw)
                # 从Js中提取的文章URL可能带引号
                urls = []
                for href in matched:
                    href = href.strip("\"' ")
                    if href.startswith("/"):
                        parsed = urlparse(url)
                        href = "{}://{}{}".format(parsed.scheme, parsed.netloc, href)
                    if _skip_article_url(href):
                        continue
                    if href not in urls and len(href) > 20:
                        urls.append(href)
                    if len(urls) >= max_articles:
                        break
            else:
                soup = BeautifulSoup(raw, "html.parser")
                links = soup.select(selector)
                urls = []
                for a in links:
                    href = a.get("href", "")
                    if href and len(href) > 20:
                        if href.startswith("/"):
                            parsed = urlparse(url)
                            href = "{}://{}{}".format(parsed.scheme, parsed.netloc, href)
                        if href.startswith("http") and len(href) > 30:
                            if _skip_article_url(href):
                                continue
                            if not any(x in href.lower() for x in ["/tag/", "/category/", "/author/", "/page/", "#"]):
                                title = (a.get_text() or "").strip()
                                if _PROMO_RE.search(title) or score_article({"title": title, "summary": "", "source": name}) < 0:
                                    continue
                                if href not in urls:
                                    urls.append(href)
                                if len(urls) >= max_articles:
                                    break
            if urls:
                new_count = 0
                for u in urls:
                    fp = get_article_fingerprint(u, name)
                    if fp not in seen:
                        total.append({"source": name, "url": u})
                        new_count += 1
                print("    {:30s} {} 篇 (新{}篇)".format(name, len(urls), new_count))
            else:
                print("    {:30s} (无)".format(name))
        except Exception as e:
            print("    {:30s} (!) {}".format(name, str(e)[:80]))
    extra = discover_priority_homepages(state, max_articles=12)
    total.extend(extra)
    print("    共发现 {} 篇新文章".format(len(total)))
    return total


def extract_keywords(text, keyword_list):
    """从文本中匹配关键词（精确匹配，短词用\\b边界）"""
    found = set()
    for kw in keyword_list:
        if _is_tag_noise(kw):
            continue
        if len(kw) <= 5:
            if re.search(r'\b' + re.escape(kw) + r'\b', text, re.IGNORECASE):
                found.add(kw)
        elif kw.lower() in text.lower():
            found.add(kw)
    return sorted(found)


_VENDOR_TAG_NOISE = {
    "crowdstrike", "kaspersky", "rapid7", "talos", "virustotal",
    "microsoft", "cisco", "mandiant", "sentinelone", "paloalto",
    "unit 42", "bleepingcomputer", "affairs", "securityweek",
    "hunt.io", "huntio", "bar", "ja4", "ja3", "jarm",
    "ai-infra-guard",
}

_TITLE_PREFIX_NOISE = re.compile(
    r"^(?:announcing|introducing|reimagining|unlock(?:ing)?|hunting|"
    r".*year in review|.*patch tuesday|urlx\b)\b",
    re.I,
)

_ACTOR_LIKE_RE = re.compile(
    r"^(?:APT(?:-C)?-?\d+|UNC\d+|TA\d+|UTA\d+|UAC-\d+|FIN\d+|"
    r"UTG-[A-Z0-9-]+|"
    r"[A-Za-z]+ (?:Typhoon|Spider|Bear|Panda|Jackal|Chollima|Blizzard))\b",
    re.I,
)


def _is_tag_noise(name):
    n = (name or "").strip().lower()
    if not n or n in _VENDOR_TAG_NOISE:
        return True
    if len(n) <= 3 and not n.startswith("apt"):
        return True
    return False


def extract_threat_from_title(title):
    """标题冒号前只有像 APT/UNC 或已在名单里的名字才当行为者，产品公告不当标签。"""
    if not title:
        return []
    names = []
    colon = title.find(": ")
    dash = title.find(" – ")
    if colon > 0 and colon < 60:
        names.append(title[:colon].strip())
    if dash > 0 and dash < 60:
        names.append(title[:dash].strip())
    known = {x.lower() for x in THREAT_ACTORS} | {x.lower() for x in MALWARE_NAMES}
    out = []
    for n in names:
        if _is_tag_noise(n) or _TITLE_PREFIX_NOISE.search(n):
            continue
        if n.lower() in known or _ACTOR_LIKE_RE.search(n):
            if n not in out:
                out.append(n)
    return out


def _apply_title_tags(article):
    title_name = extract_threat_from_title(article.get("title", ""))
    actors = article.get("threat_actors") or []
    malware = article.get("malware") or []
    for n in title_name:
        if n not in actors and n not in malware:
            actors.append(n)
    article["threat_actors"] = actors
    article["malware"] = malware


# "ssl.asp?ver=1.2.3.30"、"版本 5.0.0.1" 里的四段版本号会被当成 IP
_VERSION_IP_RE = re.compile(
    r"(?:\bver(?:sion)?\s*[=:：]?\s*v?|版本\s*[:：]?\s*v?|\bv)(\d{1,3}(?:\.\d{1,3}){3})\b", re.I)


def extract_iocs(text):
    iocs = _shared_extract_iocs(
        text,
        valid_ip=_is_relevant_ip,
        valid_domain=_is_relevant_domain,
        valid_url=_is_relevant_url,
    )
    versions = set(_VERSION_IP_RE.findall(text or ""))
    if versions and iocs.get("ip"):
        iocs["ip"] = [ip for ip in iocs["ip"] if ip.split(":")[0] not in versions]
    return iocs


def _has_hard_iocs(iocs, min_count=2):
    """IP / 哈希这类不靠上下文就能用的指标；域名、URL 容易是引用链接，不算。"""
    return sum(len((iocs or {}).get(k) or []) for k in ("ip", "md5", "sha1", "sha256")) >= min_count


def _is_relevant_ip(ip):
    """公网单播 IP 校验（含 x.x.x.0 / x.x.x.255 / 组播 / 文档网段过滤）"""
    return _shared_valid_ip(ip)


# Elastic / Kibana 文章里的 ECS 字段名（container.id、user.name）撞上了 .id / .name 真 TLD
_ECS_FIELD_ROOTS = {
    "agent", "client", "cloud", "container", "destination", "device", "dll", "dns", "ecs",
    "event", "file", "group", "host", "kibana", "network", "observer", "orchestrator",
    "process", "registry", "related", "rule", "server", "service", "source", "threat",
    "user", "winlog",
}


def _is_ecs_field(domain):
    parts = (domain or "").lower().split(".")
    return len(parts) >= 2 and parts[0] in _ECS_FIELD_ROOTS and parts[-1] in ("id", "name")


def _is_relevant_domain(domain):
    """
    域名校验。走共用实现（TLD 白名单），再叠加本模块的来源站点排除表，
    避免把新闻站自身域名和代码片段当成 IOC。
    """
    if _is_ecs_field(domain):
        return False
    return _shared_valid_domain(
        domain,
        exclude_substrings=tuple(EXCLUDE_DOMAINS) + tuple(EXCLUDE_DOMAIN_PATTERNS),
    )


def _is_relevant_url(url):
    """按 URL 主机名做边界匹配，避免 "t.co" 之类短模式误杀路径里含该串的 URL。"""
    try:
        host = urlparse(url if "://" in url else "http://" + url).netloc
    except ValueError:
        return False
    host = host.split("@")[-1].split(":")[0].lower()
    if not host:
        return False
    return not domain_matches_exclusion(host, EXCLUDE_DOMAINS)


# ============================================================
# 主逻辑
# ============================================================
def print_banner():
    print("=" * 70)
    print("  RSS威胁情报监控器 v3")
    print("  监控 {} 个Feed源".format(len(RSS_FEEDS)))
    print("  输出: {}/intel/ 和 {}/iocs/".format(OUTPUT_DIR, OUTPUT_DIR))
    print("=" * 70)


def list_feeds():
    print_banner()
    print()
    for i, (name, url) in enumerate(sorted(RSS_FEEDS.items()), 1):
        p = "★" if name in PRIORITY_FEEDS else " "
        print("  {}. [{}] {:<35s} {}".format(i, p, name, url))
    print("\n  ★ = 高优先级（含IOC概率高）")


def show_stats():
    state = load_state()
    print_banner()
    print("\n  状态文件:", STATE_FILE)
    print("  已发现文章:", state.get("total_discovered", 0))
    print("  已见URL数:", len(state.get("seen_urls", {})))
    print("  上次检查:", state.get("last_check", "从未"))
    print()


def check_feeds(force=False, discover=False):
    state = load_state()
    seen = state.get("seen_urls", {})
    print_banner()
    print("\n  状态: {}条已见 | Force: {} | Discover: {}\n".format(len(seen), "是" if force else "否", "是" if discover else "否"))

    new_articles = []
    feed_stats = []
    too_old = []

    def check_feed(name, url):
        if name in RSS_SKIP_FEEDS:
            return name, 0, 0
        arts = fetch_feed(url)
        if not arts:
            return name, 0, 0
        n = 0
        for a in arts:
            if _skip_article_url(a.get("url", "")):
                continue
            if _is_too_old(a.get("published")):
                too_old.append(name)
                continue
            fp = get_article_fingerprint(a["url"], a["title"])
            if fp not in seen or force:
                a["source"] = name
                new_articles.append(a)
                n += 1
        return name, len(arts), n

    with ThreadPoolExecutor(max_workers=10) as ex:
        fs = {ex.submit(check_feed, n, u): n for n, u in RSS_FEEDS.items()}
        for f in as_completed(fs):
            feed_stats.append(f.result())

    state["total_discovered"] = state.get("total_discovered", 0) + sum(s[2] for s in feed_stats)

    print("  Feed检查完成:\n")
    for name, c, n in sorted(feed_stats, key=lambda x: x[2], reverse=True):
        m = " ★" if n > 0 else ""
        if n > 0 or c > 0:
            print("    {:<35s} {:3d}篇, {}条新{}".format(name, c, n, m))

    total_new = sum(s[2] for s in feed_stats)
    empty_feeds = [name for name, c, n in feed_stats if c == 0 and name not in RSS_SKIP_FEEDS]
    print("\n  " + "=" * 55)
    print("  总计新文章: {} 篇".format(total_new))
    if MAX_ARTICLE_AGE_DAYS:
        print("  超过 {} 天的旧文章跳过: {} 篇".format(MAX_ARTICLE_AGE_DAYS, len(too_old)))
    if empty_feeds:
        print("  Feed 无条目/失败: {} 个".format(len(empty_feeds)))
        print("    {}".format(", ".join(empty_feeds[:18])))

    if new_articles:
        # 同一 URL 可能出现在 Mandiant / Google TI 双源
        uniq = []
        seen_fp = set()
        for a in new_articles:
            fp = get_article_fingerprint(a.get("url", ""))
            if not fp or fp in seen_fp:
                continue
            seen_fp.add(fp)
            uniq.append(a)
        new_articles = uniq
        # 情报价值评分筛选：只下载有价值的文章
        scored = [(score_article(a), a) for a in new_articles]
        scored.sort(key=lambda x: x[0], reverse=True)

        # 显示评分
        print("\n  --- 文章情报评分（只下载 ≥15 分的文章）---")
        for s, a in scored[:30]:
            m = " ★" if s >= 15 else "  "
            print("    [{:3d}]{} {:<30s} {}".format(s, m, a.get("source","")[:28], a["title"][:50]))
        if len(scored) > 30:
            print("    ... (共{}篇, 显示前30)".format(len(scored)))

        # 过滤：只下载评分 >= 15 的文章（含CVE关键词 或 威胁行为者 或 恶意软件分析）
        to_download = []
        for s, a in scored:
            if s >= 15 or force:
                to_download.append(a)
            else:
                _remember_seen(seen, a)
        max_dl = FORCE_MAX_DOWNLOAD if force else MAX_DOWNLOAD
        if len(to_download) > max_dl:
            # 超限的高分文不记 seen，下一轮还能排到
            to_download = to_download[:max_dl]

        if not to_download:
            print("\n  没有达到评分阈值的文章。")
            save_state(state)
            return []

        print("\n  --- 下载 {} 篇情报文章 ---".format(len(to_download)))
        downloaded = []

        def dl(art):
            r = download_article(art["url"])
            return {**art, **r} if r else None

        with ThreadPoolExecutor(max_workers=5) as ex:
            fs = {ex.submit(dl, a): a for a in to_download}
            done = 0
            for f in as_completed(fs):
                r = f.result()
                if r:
                    downloaded.append(r)
                done += 1
                if done % 10 == 0:
                    print("    {}/{}".format(done, len(to_download)))

        print("    成功: {}/{}".format(len(downloaded), len(to_download)))
        fresh = []
        for a in downloaded:
            if _is_too_old(a.get("published") or a.get("page_published")):
                _remember_seen(seen, a)
            else:
                fresh.append(a)
        if len(fresh) < len(downloaded):
            print("    页面发布时间超过 {} 天，丢弃: {} 篇".format(
                MAX_ARTICLE_AGE_DAYS, len(downloaded) - len(fresh)))
        downloaded = fresh

        print("\n  --- 提取威胁情报 ---")
        for a in downloaded:
            a["threat_actors"] = extract_keywords(a["content"], THREAT_ACTORS)
            a["malware"] = extract_keywords(a["content"], MALWARE_NAMES)
            _apply_title_tags(a)
            a["iocs"] = extract_iocs(a["content"])
            a["crawl_time"] = datetime.now().isoformat()
            _remember_seen(seen, a)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        intel_file = os.path.join(INTEL_DIR, "rss_intel_{}.json".format(ts))
        with open(intel_file, "w", encoding="utf-8") as f:
            json.dump(downloaded, f, ensure_ascii=False, indent=2)

        ioc_file = os.path.join(IOC_DIR, "rss_iocs_{}.json".format(ts))
        ioc_json_data = []
        for a in downloaded:
            for t, vs in a.get("iocs", {}).items():
                for v in vs[:MAX_IOCS_PER_TYPE]:
                    ioc_json_data.append({
                        "source": a.get("source", ""),
                        "url": a["url"],
                        "title": a["title"],
                        "ioc_type": t,
                        "ioc_value": v,
                        "threat_actors": a.get("threat_actors", []),
                        "malware": a.get("malware", []),
                        "crawl_time": a.get("crawl_time", "")
                    })
        with open(ioc_file, "w", encoding="utf-8") as f:
            json.dump(ioc_json_data, f, ensure_ascii=False, indent=2)
        write_iocs(ioc_json_data, source="", log_url="rss_intel_monitor")

        ioc_counts = {}
        for a in downloaded:
            for t, vs in a.get("iocs", {}).items():
                ioc_counts[t] = ioc_counts.get(t, 0) + len(vs)

        actors, malwares = set(), set()
        for a in downloaded:
            actors.update(a.get("threat_actors", []))
            malwares.update(a.get("malware", []))

        print("\n  " + "=" * 55)
        print("  文章: {} 篇 | IOC: {}个".format(len(downloaded), sum(ioc_counts.values())))
        print("  类型: {}".format(", ".join("{}={}".format(k, v) for k, v in sorted(ioc_counts.items()))))
        try:
            print("  行为者: {}".format(", ".join(sorted(actors)) or "无"))
            print("  恶意软件: {}".format(", ".join(sorted(malwares)) or "无"))
        except UnicodeEncodeError:
            print("  行为者/恶意软件: (含无法在当前控制台显示的字符)")
        print("\n  输出:")
        print("    " + intel_file)
        print("    " + ioc_file)
        print()
        save_state(state)

    # URL发现（--discover 或 --full 模式）
    if discover:
        url_articles = discover_articles(state, max_articles=30)
        if url_articles:
            print("\n  --- 下载 {} 篇博客文章 ---".format(len(url_articles)))
            url_results = []

            def dl_url(art):
                r = download_article(art["url"])
                return {**art, **r} if r else None

            old_url = 0
            with ThreadPoolExecutor(max_workers=5) as ex:
                fs = {ex.submit(dl_url, a): a for a in url_articles[:80]}
                done = 0
                for f in as_completed(fs):
                    r = f.result()
                    if r:
                        if _is_too_old(r.get("page_published")):
                            _remember_seen(seen, r)
                            old_url += 1
                            done += 1
                            continue
                        r["iocs"] = extract_iocs(r.get("content", ""))
                        # 首页文章已下载正文：标题评分低但带 IOC 附录的分析文照样收
                        if not force and score_article(r) < 15 and not _has_hard_iocs(r["iocs"]):
                            _remember_seen(seen, r)
                            done += 1
                            continue
                        r["threat_actors"] = extract_keywords(r.get("content", ""), THREAT_ACTORS)
                        r["malware"] = extract_keywords(r.get("content", ""), MALWARE_NAMES)
                        _apply_title_tags(r)
                        r["crawl_time"] = datetime.now().isoformat()
                        url_results.append(r)
                        _remember_seen(seen, r)
                    done += 1
            if old_url:
                print("    页面发布时间超过 {} 天，丢弃: {} 篇".format(MAX_ARTICLE_AGE_DAYS, old_url))

            if url_results:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                url_file = os.path.join(INTEL_DIR, "url_intel_{}.json".format(ts))
                with open(url_file, "w", encoding="utf-8") as f:
                    json.dump(url_results, f, ensure_ascii=False, indent=2)

                url_ioc_file = os.path.join(IOC_DIR, "url_iocs_{}.json".format(ts))
                url_ioc_json_data = []
                for a in url_results:
                    for t, vs in a.get("iocs", {}).items():
                        for v in vs[:MAX_IOCS_PER_TYPE]:
                            url_ioc_json_data.append({
                                "source": a.get("source", ""),
                                "url": a["url"],
                                "title": a.get("title", ""),
                                "ioc_type": t,
                                "ioc_value": v,
                                "threat_actors": a.get("threat_actors", []),
                                "malware": a.get("malware", []),
                                "crawl_time": a.get("crawl_time", "")
                            })
                with open(url_ioc_file, "w", encoding="utf-8") as f:
                    json.dump(url_ioc_json_data, f, ensure_ascii=False, indent=2)
                write_iocs(url_ioc_json_data, source="", log_url="url_intel_monitor")

                ioc_counts = {}
                for a in url_results:
                    for t, vs in a.get("iocs", {}).items():
                        ioc_counts[t] = ioc_counts.get(t, 0) + len(vs)

                actors, malwares = set(), set()
                for a in url_results:
                    actors.update(a.get("threat_actors", []))
                    malwares.update(a.get("malware", []))

                print("\n  " + "=" * 55)
                print("  URL文章: {} 篇 | IOC: {}个".format(len(url_results), sum(ioc_counts.values())))
                print("  类型: {}".format(", ".join("{}={}".format(k, v) for k, v in sorted(ioc_counts.items()))))
                try:
                    print("  行为者: {}".format(", ".join(sorted(actors)) or "无"))
                except UnicodeEncodeError:
                    print("  行为者: {}".format(", ".join(sorted(actors)).encode("gbk", "replace").decode("gbk") or "无"))
                print("\n  输出:")
                print("    " + url_file)
                print("    " + url_ioc_file)
        else:
            print("\n  URL发现: 无结果")

    save_state(state)
    return new_articles


def main():
    global MAX_ARTICLE_AGE_DAYS
    if "--days" in sys.argv:
        i = sys.argv.index("--days")
        try:
            MAX_ARTICLE_AGE_DAYS = max(0, int(sys.argv[i + 1]))
        except (IndexError, ValueError):
            print("  --days 需要一个整数天数，例如 --days 30")
            return
    if "--list" in sys.argv:
        list_feeds()
    elif "--stats" in sys.argv:
        show_stats()
    elif "--discover" in sys.argv:
        check_feeds(force="--force" in sys.argv, discover=True)
    else:
        check_feeds(force="--force" in sys.argv, discover="--full" in sys.argv)


if __name__ == "__main__":
    main()
