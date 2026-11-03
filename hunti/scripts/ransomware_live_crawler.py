"""
ransomware.live 暗网勒索事件采集（免费 API v2，无需 Key）

  https://api.ransomware.live/v2/recentvictims       最新 100 条泄露站公布
  https://api.ransomware.live/v2/victims/{YYYY}/{MM}  按月受害者，用于补齐历史
  https://api.ransomware.live/v2/groups               团伙档案：简介、工具、ATT&CK、泄露站

输出（只给 Web 面板的暗网动态用，受害者名单不是 IOC，不写 ioc_data.db）：
  output/intel/rl_victims_<时间>.json   本轮新增受害事件
  output/intel/rl_groups.json           团伙档案快照（每轮覆盖）

数据来自 ransomware.live，展示时需注明出处；免费接口有频率限制，默认每次请求间隔 2 秒。

用法:
  py -X utf8 ransomware_live_crawler.py              # 最近 + 本月 + 上月
  py -X utf8 ransomware_live_crawler.py --months 6   # 首次补齐近 6 个月
"""
import argparse
import json
import os
import time
from datetime import datetime

import requests

from crawler_utils import BASE_DIR, fingerprint, load_state, mark_many_seen, save_state

API = "https://api.ransomware.live/v2"
MODULE = "ransomware_live"
INTEL_DIR = os.path.join(BASE_DIR, "output", "intel")
os.makedirs(INTEL_DIR, exist_ok=True)
DELAY = 2.0

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) hunti-intel/1.0",
    "Accept": "application/json",
})


def _log(*args):
    print(*args, flush=True)


def _get_json(path, retries=3):
    last = None
    for attempt in range(1, retries + 1):
        try:
            r = session.get(API + path, timeout=60)
            if r.status_code == 429:
                time.sleep(10 * attempt)
                continue
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as e:
            last = e
            time.sleep(min(10, attempt * 3))
    raise RuntimeError("{} 请求失败: {}".format(path, last))


def _clean(v):
    if v is None:
        return ""
    s = str(v).strip()
    return "" if s.lower() in ("none", "null", "n/a", "false") else s


def _key(v):
    return fingerprint(_clean(v.get("group")).lower(), _clean(v.get("victim")).lower(), _clean(v.get("discovered"))[:10])


def _month_list(n):
    now = datetime.now()
    y, m = now.year, now.month
    out = []
    for _ in range(max(1, n)):
        out.append((y, m))
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return out


def main():
    parser = argparse.ArgumentParser(description="ransomware.live 暗网勒索事件采集")
    parser.add_argument("--months", type=int, default=2, help="按月补齐最近几个月（默认 2：本月 + 上月）")
    args = parser.parse_args()

    _log("=" * 60)
    _log("  ransomware.live 暗网勒索事件采集")
    _log("  " + API)
    _log("=" * 60)

    rows, failed = [], []
    try:
        recent = _get_json("/recentvictims")
        rows += recent if isinstance(recent, list) else []
        _log("  最近受害者: {} 条".format(len(recent) if isinstance(recent, list) else 0))
    except RuntimeError as e:
        failed.append(str(e))
    for y, m in _month_list(args.months):
        time.sleep(DELAY)
        try:
            month = _get_json("/victims/{}/{:02d}".format(y, m))
            rows += month if isinstance(month, list) else []
            _log("  {}-{:02d} 受害者: {} 条".format(y, m, len(month) if isinstance(month, list) else 0))
        except RuntimeError as e:
            failed.append(str(e))

    time.sleep(DELAY)
    try:
        groups = _get_json("/groups")
        if isinstance(groups, list) and groups:
            path = os.path.join(INTEL_DIR, "rl_groups.json")
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(groups, f, ensure_ascii=False)
            os.replace(tmp, path)
            _log("  团伙档案: {} 个 -> {}".format(len(groups), path))
    except RuntimeError as e:
        failed.append(str(e))

    state = load_state(MODULE)
    seen = state.get("seen_fingerprints", {})
    new, fps, batch = [], [], set()
    for v in rows:
        if not isinstance(v, dict) or not _clean(v.get("victim")):
            continue
        fp = _key(v)
        if fp in seen or fp in batch:
            continue
        batch.add(fp)
        fps.append(fp)
        new.append({k: _clean(v.get(k)) for k in (
            "victim", "group", "country", "activity", "discovered", "attackdate", "domain",
            "description", "data_size", "ransom", "screenshot", "url", "claim_url", "press")})

    if new:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = os.path.join(INTEL_DIR, "rl_victims_{}.json".format(ts))
        with open(out, "w", encoding="utf-8") as f:
            json.dump(new, f, ensure_ascii=False, indent=1)
        mark_many_seen(MODULE, fps)
        _log("  新增受害事件: {} 条 -> {}".format(len(new), out))
    else:
        save_state(MODULE, state)
        _log("  新增受害事件: 0 条（均已采集过）")
    for msg in failed:
        _log("  [FAIL] " + msg)
    _log("  本轮拉取: {} 条, 新增: {}".format(len(rows), len(new)))
    _log("  数据来源: ransomware.live（不写入 ioc_data.db）")
    if failed and not rows:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
