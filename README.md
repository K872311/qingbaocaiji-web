# hunti 威胁情报采集与研判平台

自动从公开情报源和安全博客采集 IOC（IP / 域名 / URL / 文件哈希），统一写入本地 SQLite 情报库 `ioc_data.db`，并提供一个 Web 面板做查询、批量研判、APT / 家族专题和暗网勒索动态浏览。

- **采集**：`scripts/run_all.py` 一键跑完所有采集步骤，只入库新增的 IOC。
- **研判**：`scripts/app.py` 启动 Web 面板，同事在局域网里用浏览器即可查询。

---

## 一、目录结构

```
hunti/
├── config/                     配置与密钥（密钥文件均已加入 .gitignore）
│   ├── config.ini              本机配置：情报库路径等（不提交）
│   ├── config.ini.example      配置模板，分享项目时用它
│   ├── manual_domains.txt      手工录入的恶意域名
│   ├── threatfox_auth_key.txt  ThreatFox Auth-Key（可选）
│   ├── otx_api_key.txt         OTX API Key（OTX 步骤必需）
│   ├── tc_feed_token.txt       ThreatCluster tc_live_ Key（可选）
│   └── abuseipdb_api_key.txt   AbuseIPDB Key（可选，面板实时信誉用）
├── scripts/                    所有脚本
│   ├── run_all.py              一键采集管道
│   ├── app.py                  Web 面板（Flask）
│   ├── templates/ static/      面板前端
│   └── *_crawler.py 等         各情报源采集器
└── output/                     运行产物（自动生成，不提交）
    ├── intel/                  情报文章 JSON、暗网事件、ETDA 别名库、关注列表
    ├── iocs/                   各来源每轮新增 IOC 的 JSON
    ├── history/ history_state/ 去重状态与增量历史
    ├── ip_enrich/              IP 画像源数据
    ├── family_index.db         恶意家族索引（加速面板检索）
    └── new_iocs_<时间>.csv     每轮新入库的 IOC 清单
```

---

## 二、环境准备

需要 Python 3.10 及以上（项目在 3.13 上运行），安装三个第三方库：

```powershell
pip install requests beautifulsoup4 flask
```

### 1. 配置情报库路径

复制模板并填写库路径：

```powershell
copy config\config.ini.example config\config.ini
```

```ini
[IOC Database]
; 留空则使用 output/ioc_data.db（不存在会自动建表）
ioc_db_path = D:\path\to\ioc_data.db
```

### 2. 配置 API Key（按需）

Key 放在 `config/` 下对应的 txt 文件里（每个文件一行，`#` 开头的行是注释），或用环境变量。**不要写进源码。**

| 情报源 | 文件 | 环境变量 | 不配置会怎样 |
| --- | --- | --- | --- |
| ThreatFox | `threatfox_auth_key.txt` | `THREATFOX_AUTH_KEY` | 只拉公开导出，没有近 1–7 天 API 数据 |
| OTX | `otx_api_key.txt` | `OTX_API_KEY` | OTX 这一步直接跳过 |
| ThreatCluster | `tc_feed_token.txt` | `TC_KEY` | 只拉公开 IOC / MISP，没有认证 MISP |
| isMalicious | `ismalicious_api_key.txt` | `ISMALICIOUS_API_KEY` | 只能拿到约 10% 的样本名单 |
| AbuseIPDB | `abuseipdb_api_key.txt` | `ABUSEIPDB_API_KEY` | 面板不显示 AbuseIPDB 实时信誉 |

isMalicious 的内容是 `base64(apiKey:apiSecret)`；ThreatCluster 要用 Settings 里的 `tc_live_` 开头的 Key。

---

## 三、使用方法

以下命令都在 `scripts/` 目录下执行。

### 1. 一键采集（日常使用）

```powershell
cd scripts
py -3 -X utf8 run_all.py                 # 跑完全部采集步骤
py -3 -X utf8 run_all.py --full-export   # 额外导出全量 all_iocs_*.json（约 500MB）
```

- 每一步都直接写库，库里已有的 IOC 自动跳过。
- 跑完会在 `output/new_iocs_<时间>.csv` 列出**本轮新入库**的 IOC；没有新增就不生成文件。
- 整轮耗时主要在 MISP（首次全量可能几个小时，之后每天只补新数据）。
- 适合用 Windows 任务计划每天定时跑一次。

### 2. 单独运行某个采集器

每个脚本都可以独立运行，常用参数：

| 参数 | 作用 |
| --- | --- |
| `--db <路径>` | 写入指定的库（不改 config.ini 做测试时很有用） |
| `--no-db` | 只采集、保存 JSON，不写库 |

示例：

```powershell
py -3 -X utf8 rss_intel_monitor.py --full     # RSS + 博客首页
py -3 -X utf8 rss_intel_monitor.py --list     # 列出所有订阅源
py -3 -X utf8 rss_intel_monitor.py --days 30  # 只要近 30 天的文章（默认 14）
py -3 -X utf8 threatfox_crawler.py --recent-only --days 3
py -3 -X utf8 otx_crawler.py --days 180 --include-ip
py -3 -X utf8 ip_enrich.py --lookup 1.2.3.4   # 命令行查 IP 画像
py -3 -X utf8 family_index.py --full          # 全量重建家族索引
```

### 3. 手工录入恶意域名

编辑 `config/manual_domains.txt`，每行一条，可带家族和来源；支持 `[.]`、`hxxp` 这类去活写法：

```
evil-c2.com
bad[.]example[.]net, AsyncRAT
hxxps://phish.example.org/login, Phishing, 内部通报
```

下次 `run_all.py` 会自动入库（也可以单独跑 `manual_domains_importer.py`）。

### 4. 启动 Web 面板

```powershell
py -3 -X utf8 app.py
```

- 默认监听 `0.0.0.0:5000`，启动时会打印本机和局域网访问地址。同事打不开时，检查 Windows 防火墙是否放行 TCP 5000。
- 只给本机用：`set HUNTI_WEB_HOST=127.0.0.1`
- 换端口：`set HUNTI_WEB_PORT=8080`
- 指定情报库：`set HUNTI_WEB_DB=D:\path\ioc_data.db`（不设则依次找 `scripts/ioc_data.db`、`config.ini` 里的路径）

> 面板**没有登录验证**，局域网内任何人都能访问，也能提交情报、修改关注列表。请只在可信网络内使用。

---

## 四、采集管道与情报源

`run_all.py` 按顺序执行以下步骤：

| 步骤 | 脚本 | 情报源 | 采集内容 | 入库 |
| --- | --- | --- | --- | --- |
| 1 | `rss_intel_monitor.py` | 124 个 RSS + 38 个博客首页（见下文） | 安全文章全文，从正文提取 IOC、APT 组织、恶意家族 | ✅ |
| 2 | `threatcluster_crawler.py` | [ThreatCluster](https://threatcluster.io/) | 公开高置信 IP / 域名、MISP 事件与哈希、暗网受害者 | ✅ |
| 3 | `threatfox_crawler.py` | [ThreatFox (abuse.ch)](https://threatfox.abuse.ch/) | 近 6 个月全量未过期 IOC，带恶意家族 | ✅ |
| 4 | `derp_crawler.py` | [derp.ca](https://www.derp.ca/) | 恶意软件家族列表、研究文章中的 C2 / IOC | ✅ |
| 5 | `misp_feeds_crawler.py` | [MISP Default Feeds](https://www.misp-project.org/feeds/) + MalwareBazaar | 官方公开源的域名 / URL / 哈希（默认不收 IP），外加 Binary Defense、blocklist.de、CINS、Emerging Threats 等封锁名单 | ✅ |
| 6 | `otx_crawler.py` | [AlienVault OTX](https://otx.alienvault.com/) | 近 6 个月带家族 / APT / ATT&CK 上下文的高质量 Pulse（需 Key） | ✅ |
| 7 | `hunters_ledger_crawler.py` | [The Hunter's Ledger](https://the-hunters-ledger.com/) | 战役报告的结构化 IOC，只收高置信 | ✅ |
| 7b | `manual_domains_importer.py` | `config/manual_domains.txt` | 手工录入的恶意域名 | ✅ |
| 7c | `ransomware_live_crawler.py` | [ransomware.live](https://www.ransomware.live/) | 勒索团伙泄露站公布的受害者、团伙档案 | ❌ 仅面板展示 |
| 7d | `etda_loader.py` | [ETDA Threat Group Cards](https://apt.etda.or.th/) | APT 组织别名库（搜 APT28 能匹配 Fancy Bear / Sofacy） | ❌ 仅面板使用 |
| 7e | `ismalicious_crawler.py` | [isMalicious](https://ismalicious.com/blocklist) | C2 IP / C2 域名 / 勒索域名（过滤 CDN 和博彩站后入库） | ✅ |
| 7f | `ip_enrich.py` | Spamhaus DROP、Tor 出口、Cloudflare / AWS / Azure / GCP / Oracle / 阿里云 / Fastly 网段、X4BNet / NordVPN / ProtonVPN、HTTP / SOCKS5 代理列表 | IP 属性画像（Tor、CDN、云、VPN、代理） | ✅ 以 `ip_profile` 类型入库，只作标签，不算恶意 |
| 7g | `c2intel_crawler.py` | [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds) | 近 30 天 Cobalt Strike / Sliver / Havoc 等 C2 IP 与域名 | ✅ |
| 7h | `tweetfeed_crawler.py` | [TweetFeed](https://github.com/0xDanielLopez/TweetFeed) | 研究员在 X/Twitter 上公开分享的 IOC | ✅ |
| 7i | `family_index.py` | 本地情报库 | 增量更新恶意家族索引，加速面板检索 | — |
| 8 | `export_iocs.py` | 各来源 JSON | 仅 `--full-export` 时运行，生成全量汇总 | — |

入库时会统一过滤噪音：CDN 边缘 IP、公共 DNS、私网地址、安全厂商和报告站点自身的域名、被借用做域前置的正常域名等。入库使用 `INSERT OR IGNORE`，同一个 IOC 保留最先入库的来源和家族。

另外，`malpedia_loader.py` + `parse_malpedia.py` 从 [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) 文献库生成恶意家族 / APT 关键词，RSS 采集用它识别文章里的家族名。

---

## 五、情报博客清单

### 1. RSS 订阅（124 个）

**大型安全厂商研究团队（47）**

CrowdStrike、SentinelOne、SentinelOne Labs、Palo Alto Unit 42、Rapid7、Elastic Security、Check Point Research、Volexity、Microsoft Security、Fortinet、Trend Micro、Proofpoint、Cloudflare、Akamai、Cisco Talos、Cisco Security、Sophos X-Ops、ESET WeLiveSecurity、Kaspersky Securelist、Securelist RU、Malwarebytes、Zscaler、Recorded Future、ReversingLabs、Infoblox、Mandiant、Google Threat Intelligence、Google TAG、Google Online Security、IBM X-Force、Wiz Research、Huntress、Arctic Wolf、LevelBlue SpiderLabs、Fox-IT、Nextron Systems、Acronis、Seqrite、K7 Labs、Kudelski Security、Gurucul、Horizon3 AI、Wordfence、Field Effect、Avertium、SecurityScorecard、IronScales

**威胁情报 / 恶意软件分析（19）**

ANY.RUN、AhnLab ASEC、Hybrid Analysis、GreyNoise、Cyble、SOCRadar、Flare.io、StealthMole、Dark Atlas、Rewterz、Codea Intel、Infostealers、BreakGlass Intel、OpenSource Malware、Silent Push、DomainTools、Bfore AI、PolySwarm、Moonlock

**软件供应链安全（5）**

JFrog、Sonatype、Aikido、OX Security、SafeDep

**安全新闻媒体（13）**

The Hacker News、BleepingComputer、Security Affairs、Dark Reading、SecurityWeek、CyberScoop、Infosecurity Magazine、SC World、CSO Online、Daily Security Review、HackRead、Help Net Security、The Record

**政府 / CERT / 社区（7）**

CISA Advisories、CISA News、英国 NCSC、JPCERT/CC、CERT Polska、IIJ SEC、SANS ISC

**中文安全博客（5）**

CTFiot、先知社区（阿里云）、绿盟科技、奇安信 XLab、微步在线

**独立研究员 / 小团队博客（16）**

Krebs on Security、Schneier on Security、Troy Hunt、Graham Cluley、Luke Acha、DMpDump、KM Sec、RedAsgard、DenWP、Epiphany Consulting、InTheCyber、Qurium、Synaptic Systems、D3Lab、Deception.Pro、The Hunter's Ledger

**Medium 安全专栏（6）**

SlowMist（慢雾）、OSINT Team、System Weakness、InfoSec Write-ups、DarkMoonSec、SocFortress

**情报平台自带 RSS（6）**

ThreatCluster、ThreatCluster Dark Web、ThreatCluster Vulns、ThreatCluster Exploits、derp.ca Malware、derp.ca Research（其中 ThreatCluster 的暗网 / 漏洞 / 利用三个 Feed 已由专用采集器处理，RSS 步骤跳过）

### 2. 博客首页 / 栏目页直接抓取（38 个）

用于没有 RSS、RSS 失效或 RSS 内容不全的站点：

- **无 RSS 或 RSS 已失效**：Hunt.io、CyberAndRamen、KnowBe4、Mimecast、Group-IB、奇安信威胁情报中心、Socket.dev、Expel、Validin、Intezer、CyberXtron、Cyberint（暗网 / 研究两个栏目）、Morphisec、Anomali、Datadog Security Labs、Securonix、Google Identity Security、安全内参（SecRSS）病毒木马栏目、G DATA、Truesec
- **RSS 只给部分文章，补抓栏目页**：BleepingComputer、Cisco Talos、The Hacker News、Security Affairs、Securelist / Securelist RU 及其 Threat Response 栏目、Kaspersky ICS CERT、derp.ca（两个栏目）、LevelBlue、ANY.RUN 恶意软件分析栏目、The Hunter's Ledger 报告列表、Deception.Pro、Proofpoint Threat Insight、Elastic Security Labs

默认只下载近 14 天发布的文章，单轮最多 80 篇；已下载过的文章按 URL 指纹去重。

---

## 六、Web 面板功能

面板只读情报库，文章、暗网事件、关注列表等读写 `output/intel/` 下的 JSON。

| 页面 | 用途 |
| --- | --- |
| **首页 / 搜索** | 输入 IP、域名、URL、哈希或家族名 / APT 名查询。给出研判结论（恶意 / 可疑 / 未知）、命中来源、关联恶意家族、提到它的情报文章、IP 画像标签和 AbuseIPDB 信誉。域名可一键解析 A 记录，再逐个研判解析到的 IP。首页还展示本轮采集新增数量、热门组织 / 家族标签 |
| **情报动态** | 浏览采集到的安全文章，可按来源、类别（安全博客、APT 研究、战役报告、OTX 情报包等）、时间（1 / 3 / 7 / 14 / 30 天）、是否含 IOC 筛选，查看文章正文和提取出的 IOC |
| **专项情报** | APT、C2、黑产、勒索四个专题，按来源和标题 / 标签关键词自动归类 |
| **暗网动态** | ransomware.live 勒索泄露站的受害者事件，按团伙、国家、行业筛选；单条事件显示同团伙近期受害者和安全博客里提到该团伙的文章 |
| **APT / 家族** | APT 组织与恶意家族专题页：档案（含 ETDA 别名）、IOC 数量与类型分布、样例 IOC、相关文章、按月趋势 |
| **批量研判** | 粘贴 IOC 清单或一段含 IOC 的文本（如告警日志、报告原文），自动提取并逐条研判，单次最多 500 条 |
| **关注** | 把 IP / 域名 / 关键词加入关注列表（最多 500 条），之后采集到相关新 IOC 或新文章时在导航栏提示 |
| **提交情报** | 手工录入 IOC（可带家族、来源、备注），保存在 `output/intel/user_iocs.json`，查询时一起命中 |

研判结论的含义：

- **恶意**：情报库里有这条 IOC，或有情报文章提到它。
- **可疑**：本身没有记录，但它的上级命中了，例如 URL 的主机名、带端口 IP 的纯 IP 在库里。
- **未知**：没有任何命中；安全厂商或报告站点自身的域名也一律显示为未知，避免误报。
