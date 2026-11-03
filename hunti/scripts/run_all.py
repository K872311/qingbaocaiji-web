"""
一键威胁情报获取管道（自动化）
RSS → ThreatCluster → ThreatFox → derp → MISP → OTX → Hunter's Ledger → 手工域名 → ransomware.live
→ ETDA → isMalicious → IP 画像 → C2IntelFeeds → TweetFeed → 家族索引（增量）
各采集步骤自己 write_iocs 入库（ransomware.live 不入库；IP 画像以 type=ip_profile 整体同步，不算恶意）。收尾只把本轮新入库的 IOC 写到
output/new_iocs_<时间>.csv，没有新增就不生成文件。
可选 --full-export 额外跑 export_iocs.py 生成全量 all_iocs_*.json（Web 面板用）
"""
import os, sys, subprocess, shutil, time, argparse, re, csv, json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

# 寻找可用 Python（带 requests 库）
def _find_python():
    for cand in [sys.executable, "py", "python3", "python"]:
        try:
            r = subprocess.run([cand, "-c", "import requests"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return cand
        except: pass
    return sys.executable

PYTHON = _find_python()
SCRIPTS_DATA_DIR = os.path.join(OUTPUT_DIR, "scripts_data")
STATE_FILE = os.path.join(OUTPUT_DIR, "rss_monitor_state.json")
os.makedirs(SCRIPTS_DATA_DIR, exist_ok=True)


_INSERT_RE = re.compile(r"新入库:\s*(\d+)")
_PENDING_RE = re.compile(r"待写入:\s*(\d+)")
_SKIP_RE = re.compile(r"已存在跳过:\s*(\d+)")
_DB_TOTAL_RE = re.compile(r"库总量:\s*(\d+)\s*→\s*(\d+)")


def _sum_ints(pattern, text):
    return sum(int(x) for x in pattern.findall(text or ""))


def parse_db_stats(stdout):
    """从采集脚本日志里抽出写库数字。一步可能写库多次（RSS 文章 + URL）。"""
    text = stdout or ""
    return {
        "inserted": _sum_ints(_INSERT_RE, text),
        "pending": _sum_ints(_PENDING_RE, text),
        "skipped": _sum_ints(_SKIP_RE, text),
        "wrote": "新入库:" in text or "待写入:" in text,
    }


_LOG_KEEP = (
    "DB:", "待写入", "新入库", "本轮", "新 IOC", "新事件",
    "文章:", "URL文章:", "输出:", "[SKIP]", "[FAIL]",
    "总计新文章", "Feed 无条目", "新增受害事件", "团伙档案",
)


def _print_step_output(stdout, tail=50):
    """保留写库/文章摘要行，再加末尾若干行，避免 RSS 双段输出被截掉。"""
    lines = (stdout or "").strip().split("\n")
    if not lines or lines == [""]:
        return
    keep = set()
    for i, line in enumerate(lines):
        if any(h in line for h in _LOG_KEEP):
            keep.add(i)
    start = max(0, len(lines) - tail)
    keep.update(range(start, len(lines)))
    last = -2
    for i in sorted(keep):
        if last >= 0 and i > last + 1:
            print("  ...")
        print(f"  {lines[i]}")
        last = i


def run_step(name, cmd, cwd=SCRIPTS_DIR, timeout=600):
    """运行一个脚本步骤。返回 (ok, db_stats)。"""
    print(f"\n{'='*60}")
    print(f"  [{datetime.now().strftime('%H:%M:%S')}] {name}")
    print(f"  {' '.join(cmd)}")
    print(f"{'='*60}")
    t0 = time.time()
    empty = {"inserted": 0, "pending": 0, "skipped": 0, "wrote": False}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', cwd=cwd, timeout=timeout)
        elapsed = time.time() - t0
        stats = parse_db_stats(r.stdout)
        if r.stdout:
            _print_step_output(r.stdout)
        if stats["wrote"]:
            print("  >>> 本步新入库: {}  待写入: {}  已存在跳过: {}".format(
                stats["inserted"], stats["pending"], stats["skipped"],
            ))
        elif "汇总" not in name:
            print("  >>> 本步未写库（无新增或该步只导出 JSON）")
        if r.returncode != 0:
            print(f"  [FAIL] 失败 (rc={r.returncode}, {elapsed:.0f}s)")
            if r.stderr:
                for line in r.stderr.strip().split("\n")[-5:]:
                    print(f"  ERR: {line}")
            return False, stats
        print(f"  [OK] 完成 ({elapsed:.0f}s)")
        return True, stats
    except subprocess.TimeoutExpired:
        print(f"  [FAIL] 超时 ({timeout}s)")
        return False, empty
    except Exception as e:
        print(f"  [FAIL] 异常: {e}")
        return False, empty


def collect_generated_files():
    """将 scripts/ 下生成的 derp_*.json 收集到 output/scripts_data/"""
    summary = {"collected": [], "skipped": []}
    for f in os.listdir(SCRIPTS_DIR):
        src = os.path.join(SCRIPTS_DIR, f)
        if not os.path.isfile(src):
            continue
        if f.endswith(".json") and f.startswith("derp_"):
            shutil.copy2(src, os.path.join(SCRIPTS_DATA_DIR, f))
            summary["collected"].append(f)
    return summary


NEW_IOC_FIELDS = ["type", "value", "ip_only", "source", "malware"]


def write_new_iocs(log_path, run_ts):
    """把各步追加的新入库行整理成 output/new_iocs_<ts>.csv。返回 (路径, 条数, 类型计数)。"""
    rows = []
    seen = set()
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = (row.get("type"), (row.get("value") or "").lower())
                if key in seen:
                    continue
                seen.add(key)
                rows.append(row)
        os.remove(log_path)
    if not rows:
        return "", 0, {}
    path = os.path.join(OUTPUT_DIR, f"new_iocs_{run_ts}.csv")
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=NEW_IOC_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    counts = {}
    for r in rows:
        counts[r.get("type", "")] = counts.get(r.get("type", ""), 0) + 1
    return path, len(rows), counts


def main():
    parser = argparse.ArgumentParser(description="威胁情报一键管道")
    parser.add_argument(
        "--full-export",
        action="store_true",
        help="额外跑 export_iocs.py 生成全量 all_iocs_*.json（每次约 500MB）",
    )
    args = parser.parse_args()

    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    new_log = os.path.join(OUTPUT_DIR, f".new_iocs_{run_ts}.jsonl")
    if os.path.exists(new_log):
        os.remove(new_log)
    os.environ["HUNTI_NEW_IOC_LOG"] = new_log

    print("=" * 60)
    print("  威胁情报 — 一键获取管道（只输出本轮新增）")
    print(f"  开始: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    sys.path.insert(0, SCRIPTS_DIR)
    db_path = ""
    count0 = 0
    try:
        from export_to_db import db_count, resolve_db_path
        db_path = resolve_db_path()
        count0 = db_count(db_path)
        print(f"  库: {db_path}")
        print(f"  库总量起始: {count0}")
    except Exception as e:
        print(f"  [WARN] 无法读取库总量: {e}")
    print("=" * 60)

    steps = [
        ("1. RSS 情报监控", [PYTHON, "-X", "utf8", "rss_intel_monitor.py", "--full"]),
        ("2. ThreatCluster 情报", [PYTHON, "-X", "utf8", "threatcluster_crawler.py"]),
        ("3. ThreatFox 情报", [PYTHON, "-X", "utf8", "threatfox_crawler.py"]),
        ("4. derp.ca 威胁情报", [PYTHON, "-X", "utf8", "derp_crawler.py"]),
        ("5. MISP Default Feeds", [PYTHON, "-X", "utf8", "misp_feeds_crawler.py"]),
        ("6. OTX 高质量 Pulse", [PYTHON, "-X", "utf8", "otx_crawler.py"]),
        ("7. Hunter's Ledger IOC", [PYTHON, "-X", "utf8", "hunters_ledger_crawler.py"]),
        ("7b. 手工恶意域名", [PYTHON, "-X", "utf8", "manual_domains_importer.py"]),
        ("7c. ransomware.live 暗网勒索", [PYTHON, "-X", "utf8", "ransomware_live_crawler.py"]),
        ("7d. ETDA APT 别名库", [PYTHON, "-X", "utf8", "etda_loader.py"]),
        ("7e. isMalicious C2 / 勒索", [PYTHON, "-X", "utf8", "ismalicious_crawler.py"]),
        ("7f. IP 画像源（DROP/Tor/CDN/云/VPN/代理，入库 type=ip_profile）", [PYTHON, "-X", "utf8", "ip_enrich.py", "--update", "--to-db"]),
        ("7g. C2IntelFeeds C2 IP / 域名", [PYTHON, "-X", "utf8", "c2intel_crawler.py"]),
        ("7h. TweetFeed 社区 IOC", [PYTHON, "-X", "utf8", "tweetfeed_crawler.py"]),
        ("7i. 恶意家族索引（面板检索 / 专题页）", [PYTHON, "-X", "utf8", "family_index.py"]),
    ]
    if args.full_export:
        steps.append(("8. IOC 全量汇总导出", [PYTHON, "-X", "utf8", "export_iocs.py"]))

    results = []
    for name, cmd in steps:
        timeout = 600
        if "MISP" in name:
            timeout = 14400
        elif "RSS" in name:
            timeout = 900
        elif "ThreatFox" in name or "OTX" in name or "Hunter" in name:
            timeout = 1800
        ok, stats = run_step(name, cmd, timeout=timeout)
        results.append((name, ok, stats))

    # 收集文件
    print(f"\n{'='*60}")
    print("  收集生成的文件 → output/scripts_data/")
    print(f"{'='*60}")
    collected = collect_generated_files()
    print(f"  已收集: {len(collected['collected'])} 个文件")

    # 输出 summary
    print(f"\n{'='*60}")
    print("  管道执行结果")
    print(f"{'='*60}")
    all_ok = True
    insert_total = 0
    pending_total = 0
    skip_total = 0
    for name, ok, stats in results:
        status = "[OK]" if ok else "[FAIL]"
        if not ok:
            all_ok = False
        ins = stats.get("inserted", 0) if stats else 0
        pending = stats.get("pending", 0) if stats else 0
        skipped = stats.get("skipped", 0) if stats else 0
        insert_total += ins
        pending_total += pending
        skip_total += skipped
        if stats and stats.get("wrote"):
            print(f"  {status} {name}  新入库 {ins}  待写入 {pending}  跳过 {skipped}")
        else:
            print(f"  {status} {name}  未写库")

    count1 = count0
    if db_path:
        try:
            from export_to_db import db_count
            count1 = db_count(db_path)
        except Exception:
            count1 = count0

    # 统计最新的 JSON
    print(f"\n{'='*60}")
    print("  最新数据文件")
    print(f"{'='*60}")
    for prefix, label in [
        ("rss_intel_", "RSS情报文章"),
        ("url_intel_", "URL博客文章"),
        ("derp_families_", "恶意软件家族"),
        ("otx_iocs_", "OTX IOC"),
        ("thl_iocs_", "Hunter's Ledger IOC"),
        ("all_iocs_latest", "汇总IOC (output/)"),
    ]:
        dir_to_check = OUTPUT_DIR if prefix in ("all_iocs_latest", "otx_iocs_") else SCRIPTS_DIR
        if prefix in ("rss_intel_", "url_intel_"):
            dir_to_check = os.path.join(OUTPUT_DIR, "intel")
        if prefix in ("otx_iocs_", "thl_iocs_"):
            dir_to_check = os.path.join(OUTPUT_DIR, "iocs")
        files = [f for f in os.listdir(dir_to_check) if f.startswith(prefix)]
        if files:
            latest = sorted(files)[-1]
            fpath = os.path.join(dir_to_check, latest)
            size = os.path.getsize(fpath)
            print(f"  {label}: {latest} ({size//1024}KB)")

    # 汇总 history/ 下的 delta
    print(f"\n{'='*60}")
    print("  历史增量文件夹 (output/history/)")
    print(f"{'='*60}")
    history_base = os.path.join(OUTPUT_DIR, "history")
    if os.path.isdir(history_base):
        for mod in sorted(os.listdir(history_base)):
            mod_dir = os.path.join(history_base, mod)
            json_files = [f for f in os.listdir(mod_dir) if f.endswith(".json")] if os.path.isdir(mod_dir) else []
            if json_files:
                total_kb = sum(os.path.getsize(os.path.join(mod_dir, f)) for f in json_files) // 1024
                print(f"  {mod}/: {len(json_files)} 个文件 ({total_kb}KB)")

    print(f"\n  数据目录: {SCRIPTS_DATA_DIR}/")
    print(f"  历史目录: {history_base}/")
    print(f"  汇总文件: {OUTPUT_DIR}/all_iocs_latest.json")
    print(f"  Web面板: http://localhost:5000")
    print(f"  数据库: {db_path or '未配置'}")

    net = max(0, count1 - count0)
    new_path, new_n, new_counts = write_new_iocs(new_log, run_ts)
    print(f"\n{'='*60}")
    print("  入库汇总")
    print(f"{'='*60}")
    if new_path:
        print(f"  本轮新增 IOC: {new_path}")
        print(f"  新增 {new_n} 条  " + "  ".join(
            f"{k}={v}" for k, v in sorted(new_counts.items())
        ))
    else:
        print("  本轮无新增 IOC，未生成文件")
    print(f"  本轮新入库: {net}")
    print(f"  各步新入库合计: {insert_total}")
    print(f"  各步待写入合计: {pending_total}")
    print(f"  各步已存在跳过: {skip_total}")
    print(f"  库总量: {count0} → {count1}")
    print(f"  {'全部完成 [OK]' if all_ok else '部分失败 [FAIL]'}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


if __name__ == "__main__":
    t0 = time.time()
    main()
    print(f"总耗时: {(time.time()-t0)/60:.1f} 分钟")
