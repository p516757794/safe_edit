# -*- coding: utf-8 -*-
"""safe_edit 命令行：给不支持 MCP 的 AI 工具（比如 DeepSeek Harness）用，逻辑和 MCP 服务完全相同。

必须用受信任的 Python 运行，输出为 UTF-8：
  python safe_edit_cli.py [--root 白名单] status
  python safe_edit_cli.py [--root 白名单] check 路径 [更多路径 ...]
  python safe_edit_cli.py [--root 白名单] search 关键词 [--folder 子文件夹] [--regex] [--ignore-case] [--exts .c,.h] [--max 20] [--files-only]
  python safe_edit_cli.py [--root 白名单] read 路径 [--start 1] [--end 40]
  python safe_edit_cli.py [--root 白名单] apply --spec 说明.json|- [--dry-run] [--show-diff]
  python safe_edit_cli.py [--root 白名单] new --spec 说明.json|- [--dry-run] [--show-diff]
  python safe_edit_cli.py [--root 白名单] log [--since "2026-10-19 15:30"]

工作文件夹：--root > 环境变量 SAFE_EDIT_ROOT > 当前目录。白名单由 config.json 的 whitelist_root 决定，--root 不能扩大白名单；
whitelist_root 留空时，白名单就是工作文件夹。
apply 的说明（UTF-8 JSON）：{"path": "...", "base_sha256": "...", "note": "...", "edits": [{"old": "...", "new": "..."}]}
  按行号修改时每组写 {"start_line": 10, "end_line": 12, "first_line": "...", "last_line": "...", "new": "..."}
  或 {"insert_after": 10, "after_line": "...", "new": "..."}，并且必须给 base_sha256。
new 的说明：{"path": "...", "content": "...", "note": "..."}
--spec - 表示从标准输入读说明，这样磁盘上不会留下代码片段。
先 check 检查加密状态；明文或不存在的文件用普通工具处理。
apply / new 默认直接写回加密文件，diff 仅留档，不要求用户确认；只有显式 --dry-run 才只预览。
返回码：0 成功；1 出错（文件没动）；2 写回失败（工具已锁定）。
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import safe_edit_core as core  # noqa: E402


def load_spec(src):
    try:
        raw = sys.stdin.buffer.read() if src == "-" else open(src, "rb").read()
    except OSError as e:
        raise core.ToolError("说明文件读不了：%s" % e)
    try:
        spec = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as e:
        raise core.ToolError("说明不是合法的 UTF-8 JSON：%s" % e)
    if not isinstance(spec, dict):
        raise core.ToolError("说明的顶层必须是 JSON 对象")
    return spec


def build_parser():
    ap = argparse.ArgumentParser(prog="safe_edit_cli", description="safe_edit 命令行")
    ap.add_argument("--root", help="工作文件夹（默认环境变量 SAFE_EDIT_ROOT，再默认当前目录）；白名单由 config.json 的 whitelist_root 决定")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="查看状态和白名单")
    p = sub.add_parser("check", help="检查 1–50 个文件是否加密，明文用普通工具")
    p.add_argument("paths", nargs="+")
    p = sub.add_parser("search", help="搜索源码")
    p.add_argument("pattern")
    p.add_argument("--folder", default="")
    p.add_argument("--regex", action="store_true")
    p.add_argument("--ignore-case", action="store_true")
    p.add_argument("--exts", default="")
    p.add_argument("--max", type=int, default=None)
    p.add_argument("--files-only", action="store_true", help="只列命中的文件和命中数")
    p = sub.add_parser("read", help="读取指定行")
    p.add_argument("path")
    p.add_argument("--start", type=int, default=1)
    p.add_argument("--end", type=int, default=None)
    for name, desc in (("apply", "修改已有文件"), ("new", "新建文件")):
        p = sub.add_parser(name, help=desc)
        p.add_argument("--spec", required=True, help="说明文件路径，- 表示从标准输入读")
        p.add_argument("--dry-run", action="store_true", help="只看 diff，不写盘")
        p.add_argument("--show-diff", action="store_true", help="把 diff 也打印出来（默认只给 diff 文件位置）")
    p = sub.add_parser("log", help="生成修改记录")
    p.add_argument("--since", default=None)
    return ap


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass
    a = build_parser().parse_args(argv)
    if a.root:
        root, source = a.root, "命令行参数 --root"
    elif os.environ.get("SAFE_EDIT_ROOT", "").strip():
        root, source = os.environ["SAFE_EDIT_ROOT"].strip(), "环境变量 SAFE_EDIT_ROOT"
    else:
        root, source = os.getcwd(), "当前目录"
    try:
        ws = core.Workspace(root, source, client_name="safe_edit_cli")
        if a.cmd == "status":
            out = ws.tool("get_status", {})
        elif a.cmd == "check":
            out = ws.tool("check_file", {"paths": a.paths})
        elif a.cmd == "search":
            out = ws.tool("search_code", {"pattern": a.pattern, "folder": a.folder, "regex": a.regex,
                                          "ignore_case": a.ignore_case, "exts": a.exts or None,
                                          "max_results": a.max, "files_only": a.files_only})
        elif a.cmd == "read":
            out = ws.tool("read_source", {"path": a.path, "start_line": a.start, "end_line": a.end})
        elif a.cmd == "log":
            out = ws.tool("change_log", {"since": a.since})
        else:
            spec = load_spec(a.spec)
            if a.show_diff:
                spec["show_diff"] = True
            spec["dry_run"] = a.dry_run
            out = ws.tool("prepare_edit" if a.cmd == "apply" else "prepare_new_file", spec)
        print(out)
        return 0
    except core.WriteFailure as e:
        print("写回失败：%s" % e)
        return 2
    except core.ToolError as e:
        print("错误：%s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
