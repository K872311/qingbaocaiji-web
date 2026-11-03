"""
ETDA Threat Group Cards（泰国 ETDA 的 APT 组织百科）别名库

  网站: https://apt.etda.or.th/cgi-bin/listgroups.cgi
  JSON: https://apt.etda.or.th/cgi-bin/getcard.cgi?g=all&o=j

输出 output/intel/etda_groups.json，只给 Web 面板统一 APT 别名用（搜 APT28 也能匹配
Fancy Bear / Sofacy 的文章、APT 专项归类），不写 ioc_data.db。
ETDA 更新很慢，7 天内下载过就跳过；下载失败保留旧文件。

用法:
  py -X utf8 etda_loader.py           # 超过 7 天才重新下载
  py -X utf8 etda_loader.py --force   # 强制重新下载
"""
import argparse
import json
import os
import time

import requests

from crawler_utils import BASE_DIR

URL = "https://apt.etda.or.th/cgi-bin/getcard.cgi?g=all&o=j"
INTEL_DIR = os.path.join(BASE_DIR, "output", "intel")
OUT_FILE = os.path.join(INTEL_DIR, "etda_groups.json")
MAX_AGE_DAYS = 7
os.makedirs(INTEL_DIR, exist_ok=True)


def _log(*args):
    print(*args, flush=True)


def _str_list(v):
    if not v:
        return []
    if isinstance(v, str):
        v = [v]
    return [str(x).strip() for x in v if str(x).strip()]


def _group(v):
    names = []
    for n in v.get("names") or []:
        name = (n.get("name") if isinstance(n, dict) else str(n) or "").strip()
        if name and name not in names:
            names.append(name)
    if not names:
        return None
    return {
        "name": names[0],
        # showcard.cgi?g= 只认完整卡片名（"Sofacy, APT 28, Fancy Bear, Sednit"），单个别名打开是空页
        "card": str(v.get("actor") or "").strip() or names[0],
        "names": names,
        "country": [c for c in _str_list(v.get("country")) if not c.startswith("[")],
        "motivation": _str_list(v.get("motivation")),
        "first_seen": str(v.get("first-seen") or "").strip(),
        "description": str(v.get("description") or "").strip()[:2000],
        "last_card_change": str(v.get("last-card-change") or "").strip(),
    }


def main():
    parser = argparse.ArgumentParser(description="ETDA Threat Group Cards 别名库")
    parser.add_argument("--force", action="store_true", help="忽略 7 天缓存，强制下载")
    args = parser.parse_args()

    _log("=" * 60)
    _log("  ETDA Threat Group Cards（APT 组织别名库）")
    _log("  https://apt.etda.or.th/cgi-bin/listgroups.cgi")
    _log("=" * 60)
    if not args.force and os.path.isfile(OUT_FILE):
        age = (time.time() - os.path.getmtime(OUT_FILE)) / 86400
        if age < MAX_AGE_DAYS:
            _log("  [SKIP] {:.1f} 天前已下载，{} 天内不重复拉取".format(age, MAX_AGE_DAYS))
            return
    try:
        r = requests.get(URL, timeout=90, headers={"User-Agent": "Mozilla/5.0 hunti-intel/1.0"})
        r.raise_for_status()
        data = r.json()
    except (requests.RequestException, ValueError) as e:
        _log("  [FAIL] 下载失败，保留旧文件: {}".format(e))
        return
    groups = [g for g in (_group(v) for v in data.get("values") or []) if g]
    if not groups:
        _log("  [FAIL] 返回里没有组织数据，保留旧文件")
        return
    out = {
        "source": "ETDA Threat Group Cards",
        "url": "https://apt.etda.or.th/cgi-bin/listgroups.cgi",
        "last_db_change": data.get("last-db-change") or "",
        "fetched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "groups": groups,
    }
    tmp = OUT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OUT_FILE)
    _log("  组织: {}  别名: {}  ETDA 库更新: {}".format(
        len(groups), sum(len(g["names"]) for g in groups), out["last_db_change"]))
    _log("  输出: {}".format(OUT_FILE))


if __name__ == "__main__":
    main()
