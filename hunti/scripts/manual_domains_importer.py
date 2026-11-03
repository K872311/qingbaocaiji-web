"""
手工恶意域名入库

读 config/manual_domains.txt，每行一个域名，可选用逗号带家族名和来源：
  evil-c2.com
  bad[.]example[.]net, AsyncRAT
  hxxps://phish.example.org/login, Phishing, 内部通报

去掉 hxxp / [.] 这类去活写法和 URL 路径，只取主机名，校验后经 write_iocs 入库。
库里已有的 (type, value) 自动跳过，所以整份文件每次重跑也只会新增没见过的。

用法:
  py -X utf8 manual_domains_importer.py
  py -X utf8 manual_domains_importer.py --file D:\\path\\domains.txt
  py -X utf8 manual_domains_importer.py --no-db
"""
import argparse
import os
import re

from crawler_utils import BASE_DIR, is_valid_domain
from export_to_db import resolve_db_path, write_iocs

DEFAULT_FILE = os.path.join(BASE_DIR, "config", "manual_domains.txt")
DEFAULT_SOURCE = "Manual"


def _refang(text):
    t = text.strip()
    t = re.sub(r"^hxxp", "http", t, flags=re.I)
    t = t.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[dot]", ".")
    t = t.replace("[:]", ":").replace("[://]", "://")
    return t


def _host(text):
    t = _refang(text)
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", t, flags=re.I)
    t = t.split("/")[0].split("?")[0].split("#")[0]
    t = t.split("@")[-1]
    if t.count(":") == 1:
        t = t.split(":")[0]
    return t.strip().strip(".").lower()


def load_domains(path):
    rows = []
    bad = []
    seen = set()
    with open(path, "r", encoding="utf-8-sig") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            domain = _host(parts[0])
            malware = parts[1] if len(parts) > 1 else ""
            source = parts[2] if len(parts) > 2 and parts[2] else DEFAULT_SOURCE
            if not is_valid_domain(domain):
                bad.append((lineno, parts[0]))
                continue
            if domain in seen:
                continue
            seen.add(domain)
            rows.append({
                "ioc_type": "domain",
                "ioc_value": domain,
                "source": source,
                "malware": [malware] if malware else [],
            })
    return rows, bad


def main():
    parser = argparse.ArgumentParser(description="手工恶意域名入库")
    parser.add_argument("--file", default=DEFAULT_FILE)
    parser.add_argument("--no-db", action="store_true")
    parser.add_argument("--db", default="")
    args = parser.parse_args()

    print("=" * 60)
    print("  手工恶意域名入库")
    print("  文件:", args.file)
    print("=" * 60)
    if not os.path.isfile(args.file):
        print("  [SKIP] 文件不存在")
        return []

    rows, bad = load_domains(args.file)
    print("  有效域名: {}  无效: {}".format(len(rows), len(bad)))
    for lineno, text in bad[:20]:
        print("    [无效] 第 {} 行: {}".format(lineno, text))
    if not rows:
        print("  [SKIP] 无域名可写库")
        return []
    if args.no_db:
        print("  [SKIP] --no-db")
        return rows
    write_iocs(rows, resolve_db_path(args.db), log_url="manual_domains.txt")
    return rows


if __name__ == "__main__":
    main()
