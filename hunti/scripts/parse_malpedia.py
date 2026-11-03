"""
解析 malpedia.bib → 项目可直接用的文件（仅限 2025-2026 年数据）

USAGE:  python scripts/parse_malpedia.py output/malpedia.bib

产出:
  1. output/malpedia_urls.json    → 按域名分组的分析文章URL
  2. output/malpedia_urls.txt     → 纯URL列表
  3. output/malpedia_keywords.json → 恶意软件/APT名称关键词
  4. output/malpedia_keywords_py.txt → Python list片段
  5. output/malpedia_new_sources.json → 未覆盖的新域名
"""
import re, json, sys, os
from collections import Counter, defaultdict
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

START_YEAR = 2025
END_YEAR = 2026

EXCLUDE_DOMAINS_SMALL = {
    "twitter.com", "x.com", "youtube.com", "facebook.com",
    "linkedin.com", "instagram.com", "reddit.com",
    "github.com", "gitlab.com", "bitbucket.org",
    "medium.com", "blogspot.com", "t.me", "telegram.me",
    "npmjs.com", "pypi.org", "nuget.org",
    "docker.com", "docker.io", "wikipedia.org",
    "claude.ai", "chatgpt.com", "openai.com",
}


def parse_bib_entries(content):
    """将 bib 文本按条目拆分，每一条包括完整文本"""
    entries = []
    # bib 条目以 @type{key, 开始，以 }@ 或文件结尾
    i = 0
    while i < len(content):
        m = re.search(r'@(\w+)\{([^,\s]+),', content[i:])
        if not m:
            break
        start = i + m.start()
        # 找这个条目的闭合大括号（逐层匹配）
        depth = 0
        j = start
        while j < len(content):
            if content[j] == '{':
                depth += 1
            elif content[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        entries.append(content[start:j+1])
        i = j + 1
    return entries


def get_field(text, field):
    """从 bib 条目文本中提取某个字段值"""
    # 支持字段值可能跨多行
    m = re.search(rf'{field}\s*=\s*\{{([^}}]*)\}}', text)
    if m:
        return m.group(1).strip()
    # 尝试跨行匹配
    m = re.search(rf'{field}\s*=\s*\{{((?:[^}}]|\n)*?)\}}', text)
    if m:
        return m.group(1).strip()
    return ""


def is_in_year_range(date_str, start_year, end_year):
    """检查日期是否在年份范围内"""
    m = re.search(r'(\d{4})', date_str)
    if m:
        y = int(m.group(1))
        return start_year <= y <= end_year
    return False


def main():
    if len(sys.argv) < 2:
        print("用法: python scripts/parse_malpedia.py <malpedia.bib路径>")
        sys.exit(1)

    bib_path = sys.argv[1]
    if not os.path.exists(bib_path):
        print(f"[FAIL] 文件不存在: {bib_path}")
        sys.exit(1)

    with open(bib_path, "r", encoding="utf-8") as f:
        raw = f.read()

    print(f"[1] 解析条目，筛选 {START_YEAR}–{END_YEAR} 年的数据...")
    all_entries = parse_bib_entries(raw)
    print(f"    原始条目数: {len(all_entries)}")

    # 按年份过滤
    filtered_entries = [e for e in all_entries if is_in_year_range(get_field(e, "date"), START_YEAR, END_YEAR)]
    print(f"    {START_YEAR}–{END_YEAR} 条目数: {len(filtered_entries)}")

    if not filtered_entries:
        print("[WARN] 没有匹配年份的条目，检查 date 字段格式...")
        dates = Counter()
        for e in all_entries[:100]:
            dates[get_field(e, "date")[:10]] += 1
        print("    样例 dates:", list(dates.keys())[:10])
        return

    # ============ 1. 提取 URL ============
    print(f"\n[2] 提取URL...")
    all_urls = []
    domain_urls = defaultdict(list)
    domain_entry_count = Counter()

    for entry in filtered_entries:
        url = get_field(entry, "url")
        key = re.search(r'@\w+\{([^,\s]+)', entry).group(1) if re.search(r'@\w+\{([^,\s]+)', entry) else ""
        if url:
            all_urls.append({"url": url, "key": key})
            m = re.search(r"https?://([^/]+)", url)
            if m:
                d = m.group(1).lower()
                domain_urls[d].append(url)
                domain_entry_count[d] += 1

    print(f"    去重前URL: {len(all_urls)}")
    unique_urls = set(a["url"] for a in all_urls)
    print(f"    去重后URL: {len(unique_urls)}")

    # 过滤噪音域名
    filtered_domains = {}
    for d in sorted(domain_urls.keys()):
        if d not in EXCLUDE_DOMAINS_SMALL and not any(
            ex in d for ex in ["google", "facebook", "twitter", "youtube", "instagram"]
        ):
            filtered_domains[d] = sorted(set(domain_urls[d]))

    url_count = sum(len(v) for v in filtered_domains.values())
    print(f"    过滤后: {len(filtered_domains)} 个域名, {url_count} 条URL")

    # 保存 URL 清单
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    url_file = os.path.join(OUTPUT_DIR, "malpedia_urls.json")
    with open(url_file, "w", encoding="utf-8") as f:
        json.dump({
            "source": "malpedia.bib",
            "year_range": f"{START_YEAR}-{END_YEAR}",
            "total_urls": url_count,
            "total_domains": len(filtered_domains),
            "domains": filtered_domains,
        }, f, ensure_ascii=False, indent=2)
    print(f"    → {url_file}")

    # 纯 URL 列表
    flat_list = []
    for urls in filtered_domains.values():
        flat_list.extend(urls)
    url_txt = os.path.join(OUTPUT_DIR, "malpedia_urls.txt")
    with open(url_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(flat_list))
    print(f"    → {url_txt} ({len(flat_list)} 条)")

    # ============ 2. 提取恶意软件/APT名称 ============
    print(f"\n[3] 提取关键词...")
    raw_names = Counter()
    for entry in filtered_entries:
        key_m = re.search(r'@\w+\{([^,\s]+)', entry)
        if key_m:
            name = key_m.group(1).split(":")[0].strip().lower()
            if name and len(name) > 1 and not name.isdigit():
                raw_names[name] += 1

    print(f"    原始key名称: {len(raw_names)} 个")
    MIN_COUNT = 2
    keywords = sorted(
        [{"name": n, "count": c} for n, c in raw_names.items() if c >= MIN_COUNT],
        key=lambda x: -x["count"],
    )
    print(f"    过滤后(≥{MIN_COUNT}次): {len(keywords)} 个")

    kw_file = os.path.join(OUTPUT_DIR, "malpedia_keywords.json")
    with open(kw_file, "w", encoding="utf-8") as f:
        json.dump({
            "source": "malpedia.bib",
            "year_range": f"{START_YEAR}-{END_YEAR}",
            "total_unique": len(keywords),
            "keywords": keywords,
        }, f, ensure_ascii=False, indent=2)
    print(f"    → {kw_file}")

    print("\n    高频关键词 TOP 50:")
    for kw in keywords[:50]:
        print(f"      {kw['count']:4d}  {kw['name']}")

    # Python list 片段
    py_list_path = os.path.join(OUTPUT_DIR, "malpedia_keywords_py.txt")
    names_only = [kw["name"].title() for kw in keywords[:200]]
    with open(py_list_path, "w", encoding="utf-8") as f:
        f.write(f"# 来自 malpedia.bib ({START_YEAR}-{END_YEAR}) {len(keywords)} 个关键词\n")
        f.write("MALPEDIA_KEYWORDS = [\n")
        for n in names_only:
            f.write(f'    "{n}",\n')
        f.write("]\n")
    print(f"\n    → {py_list_path}")

    # ============ 3. 域名覆盖率分析 ============
    print(f"\n[4] 域名覆盖率分析...")
    existing_set = {
        "securelist.com", "kaspersky.com", "intel.breakglass.tech", "crowdstrike.com",
        "sentinelone.com", "unit42.paloaltonetworks.com", "rapid7.com",
        "elastic.co", "checkpoint.com", "volexity.com", "microsoft.com",
        "fortinet.com", "trendmicro.com", "proofpoint.com", "cloudflare.com",
        "akamai.com", "thehackernews.com", "krebsonsecurity.com",
        "welivesecurity.com", "bleepingcomputer.com", "securityaffairs.com",
        "darkreading.com", "securityweek.com", "cyberscoop.com",
        "thecyberexpress.com", "infosecurity-magazine.com", "scworld.com",
        "csoonline.com", "any.run", "asec.ahnlab.com", "jfrog.com",
        "malwarebytes.com", "hunt.io", "anomali.com", "reversinglabs.com",
        "infoblox.com", "flare.io", "socradar.io", "cyble.com",
        "recordedfuture.com", "greynoise.io", "zscaler.com", "morphisec.com",
        "isc.sans.edu", "kudelskisecurity.com", "datadoghq.com", "cert.pl",
        "gurucul.com", "securonix.com", "wordfence.com", "acronis.com",
        "secrss.com", "ctfiot.com", "xz.aliyun.com", "nsfocusglobal.com",
        "slowmist.medium.com", "osintteam.blog", "systemweakness.com",
        "infosecwriteups.com", "arcticwolf.com", "hackread.com", "moonlock.com",
        "horizon3.ai", "d3lab.net", "cyberaccord.com", "seqrite.com",
        "blog.synapticsystems.de", "blog.xlab.qianxin.com",
        "blog.talosintelligence.com",
    }

    new_domains = set(filtered_domains.keys()) - existing_set
    new_count = sum(len(filtered_domains[d]) for d in new_domains)
    overlap = existing_set & set(filtered_domains.keys())
    print(f"    已在RSS源中: {len(overlap)} 个域名")
    print(f"    未覆盖新域名: {len(new_domains)} 个 ({new_count} 条URL)")

    domain_counts = {d: len(filtered_domains[d]) for d in new_domains}
    print("\n    新域名中 URL 最多的 TOP 20:")
    for d, c in sorted(domain_counts.items(), key=lambda x: -x[1])[:20]:
        print(f"      {c:4d}  {d}")

    new_file = os.path.join(OUTPUT_DIR, "malpedia_new_sources.json")
    new_data = dict(sorted(
        [(d, filtered_domains[d]) for d in new_domains],
        key=lambda x: -len(x[1])
    ))
    with open(new_file, "w", encoding="utf-8") as f:
        json.dump({
            "year_range": f"{START_YEAR}-{END_YEAR}",
            "total_new_domains": len(new_domains),
            "total_new_urls": new_count,
            "new_sources": new_data,
        }, f, ensure_ascii=False, indent=2)
    print(f"    → {new_file}")

    print(f"\n{'='*60}")
    print(f"  统计汇总 ({START_YEAR}–{END_YEAR})")
    print(f"{'='*60}")
    print(f"  条目数      : {len(filtered_entries)}")
    print(f"  URL 总量    : {url_count}")
    print(f"  URL 域名    : {len(filtered_domains)}")
    print(f"  关键词总量  : {len(keywords)}")
    print(f"  新发现域名  : {len(new_domains)} (含 {new_count} 条URL)")
    print(f"  各文件位于  : {OUTPUT_DIR}/")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
