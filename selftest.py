# -*- coding: utf-8 -*-
"""safe_edit 自测脚本，由产品经理用受信任的 Python 运行：

    & 'C:\\Users\\Administrator\\AppData\\Local\\Programs\\Python\\Python312\\python.exe' selftest.py --sample <一个加密的源文件>

- 新建一个测试文件夹，造出各种编码、行尾的样本文件，测试读取、搜索、修改、写回、备份、锁定；
- 给了 --sample 时，用 PowerShell 按原样复制这个加密文件（复制的是密文，原文件只读不动），测试写回后仍然加密；
- 用子进程实际启动 MCP 服务和命令行各跑一遍；
- 最后删除测试文件夹（加 --keep 保留）。
测试用的配置、备份、日志、锁文件都放在测试文件夹里，不影响正式的备份目录。
"""

import argparse
import codecs
import datetime
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import safe_edit_core as core  # noqa: E402

RESULTS = []

GBK_TEXT = ("/* 温度采集模块 */\r\n#include \"main.h\"\r\n\r\nvoid Temp_Init(void)\r\n{\r\n"
            "    // 初始化 ADC\r\n    ADC_Init();\r\n}\r\n")
UTF8_TEXT = "/* 串口模块 */\n// 初始化串口\nvoid Uart_Init(void)\n{\n}\n"
BOM_TEXT = "/* 数据 */\nint g_data = 0; // 中文\n"
ASCII_TEXT = "#ifndef A_H\r\n#define A_H\r\nint a;\r\n#endif\r\n"
MIXED_TEXT = "line1\r\nline2\nline3\nline4\r\n// 中文\r\n"
DOC_TEXT = "# 说明\r\n参数：频率\r\n"
LINES_TEXT = "int a1;\r\nint a2;\r\nint a3;\r\nint a4;\r\nint a5_with_a_long_name = 5; // 很长的一行\r\n"


def check(name, fn):
    try:
        fn()
        RESULTS.append((name, True, ""))
        print("[通过] " + name)
    except Exception as e:
        detail = str(e) if isinstance(e, AssertionError) else "%s: %s" % (type(e).__name__, e)
        RESULTS.append((name, False, detail))
        print("[失败] %s：%s" % (name, detail))
        if not isinstance(e, AssertionError):
            traceback.print_exc()


def expect_error(fn, contains, cls=core.ToolError):
    try:
        fn()
    except cls as e:
        assert contains in str(e), "报错内容不对（应包含“%s”）：%s" % (contains, e)
        return str(e)
    raise AssertionError("应该报错（包含“%s”），但没有报错" % contains)


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass
    ap = argparse.ArgumentParser(description="safe_edit 自测")
    ap.add_argument("--sample", help="一个加密的源文件（只读），用来测试加密文件写回后仍然加密")
    ap.add_argument("--dir", help="测试文件夹（必须不存在），默认 E:\\soft\\_safe_edit_selftest_时间")
    ap.add_argument("--keep", action="store_true", help="测完保留测试文件夹")
    a = ap.parse_args()

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    parent = r"E:\soft" if os.path.isdir(r"E:\soft") else tempfile.gettempdir()
    base = os.path.realpath(a.dir or os.path.join(parent, "_safe_edit_selftest_" + stamp))
    if os.path.exists(base):
        print("测试文件夹已存在，停止：%s" % base)
        return 2
    proj = os.path.join(base, "proj")
    backups = os.path.join(base, "_backups")
    for d in ("Function", "Objects", "secret", "Lib"):
        os.makedirs(os.path.join(proj, d))
    os.makedirs(backups)
    print("测试文件夹：%s\n" % base)

    cfg = dict(core.DEFAULT_CONFIG)
    cfg.update({"backup_root": backups, "exclude_dirs": [backups], "deny_read": ["secret"]})
    cfg_file = os.path.join(base, "config_test.json")
    with open(cfg_file, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1)
    cfg["_path"] = cfg_file
    cfg2 = dict(cfg)
    cfg2["whitelist_root"] = base
    cfg2_file = os.path.join(base, "config_test_whitelist.json")
    with open(cfg2_file, "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in cfg2.items() if not k.startswith("_")}, f, ensure_ascii=False, indent=1)

    def p(rel):
        return os.path.join(proj, rel)

    def put(rel, data):
        with open(p(rel), "wb") as f:
            f.write(data)

    put("Function\\temp.c", GBK_TEXT.encode("gbk"))
    put("Function\\uart.c", UTF8_TEXT.encode("utf-8"))
    put("Function\\data.c", codecs.BOM_UTF8 + BOM_TEXT.encode("utf-8"))
    put("Function\\a.h", ASCII_TEXT.encode("ascii"))
    put("Function\\mixed.c", MIXED_TEXT.encode("gbk"))
    put("Function\\bad.c", "ok\r\n".encode("gbk") + b"bad \xff\xfe line\r\n")
    put("Function\\long.c", "".join("// line %d\r\n" % i for i in range(1, 401)).encode("ascii"))
    put("Function\\empty.c", b"")
    put("Function\\pad.c", "int x;        /* 对齐  注释 */\r\n".encode("gbk"))
    put("Function\\lines.c", LINES_TEXT.encode("gbk"))
    put("Function\\noeol.c", b"a = 1;\r\nb = 2;")
    put("Function\\notes.md", DOC_TEXT.encode("gbk"))
    put("Function\\readme.txt", b"Readme\r\n")
    put("Lib\\lib.c", "// 初始化 厂家库\r\n".encode("gbk"))
    put("Objects\\skip.c", "// 初始化 不应该被搜到\r\n".encode("gbk"))
    put("secret\\key.c", "// 初始化 密钥\r\n".encode("gbk"))
    put("Project.uvprojx", b"<Project></Project>\r\n")

    ws = core.Workspace(proj, "自测", cfg=dict(cfg))
    fn = lambda name: os.path.join("Function", name)  # noqa: E731

    def preview(workspace, name, args):
        """只检查底层 diff 格式；1.4.0 的公开接口另测加密分流和直接写回。"""
        if name == "prepare_edit":
            r = workspace.prepare_edit(args["path"], args["edits"],
                                       args.get("base_sha256", ""), args.get("note", ""))
            return core._fmt_prepare(r, workspace._review(r, args.get("show_diff", False)))
        r = workspace.prepare_new_file(args["path"], args["content"], args.get("note", ""))
        return core._fmt_new(r, workspace._review(r, args.get("show_diff", False)))

    def t_root():
        drive_root = "E:\\" if os.path.isdir("E:\\") else "C:\\"
        expect_error(lambda: core.Workspace(drive_root, "t", cfg=dict(cfg)), "磁盘根目录")
        expect_error(lambda: core.Workspace(os.path.expanduser("~"), "t", cfg=dict(cfg)), "用户目录")
        expect_error(lambda: core.Workspace(HERE, "t", cfg=dict(cfg)), "排除目录")
        expect_error(lambda: core.Workspace(backups, "t", cfg=dict(cfg)), "排除目录")
        assert core.Workspace(proj, "t", cfg=dict(cfg)).root == os.path.realpath(proj)

    def t_paths():
        expect_error(lambda: ws.resolve("..\\outside.c", must_exist=False), "不在白名单")
        expect_error(lambda: ws.resolve(cfg_file), "不在白名单")
        expect_error(lambda: ws.resolve("Function\\temp.c:stream"), "冒号")
        expect_error(lambda: ws.resolve("\\\\server\\share\\a.c"), "网络路径")
        expect_error(lambda: ws.resolve("secret\\key.c"), "不许读")
        expect_error(lambda: ws.resolve("Function\\nope.c"), "不存在")
        assert ws.resolve("Function\\temp.c")[1] == fn("temp.c")

    def t_read_encodings():
        r = ws.read_source("Function\\temp.c")
        assert r["encoding"] == "GBK" and r["eol"] == "CRLF" and r["total"] == 8, r
        assert "初始化 ADC" in r["body"], r["body"]
        assert ws.read_source("Function\\uart.c")["encoding"] == "UTF-8"
        assert ws.read_source("Function\\data.c")["encoding"] == "UTF-8（带 BOM）"
        assert ws.read_source("Function\\a.h")["encoding"] == "ASCII（纯英文）"
        assert ws.read_source("Function\\mixed.c")["eol"].startswith("混合")
        expect_error(lambda: ws.read_source("Function\\bad.c"), "第 2 行")

    def t_read_range():
        # 不写结束行时默认读 40 行；写了结束行也最多 300 行
        r = ws.read_source("Function\\long.c")
        assert r["start"] == 1 and r["end"] == 40 and "第 41 行" in r["note"], r["note"]
        r = ws.read_source("Function\\long.c", 5, 74)
        assert r["start"] == 5 and r["end"] == 74 and len(r["body"].splitlines()) == 70
        r = ws.read_source("Function\\long.c", 1, 350)
        assert r["end"] == 300 and "最多返回 300 行" in r["note"], r["note"]
        r = ws.read_source("Function\\long.c", 395, 500)
        assert r["end"] == 400 and r["body"].count("\n") == 5, r["body"]

    def t_search():
        r = ws.search("初始化")
        files = sorted({h[0] for h in r["hits"]})
        assert files == sorted([fn("temp.c"), fn("uart.c")]), files
        assert not r["stop"], r["stop"]
        assert fn("bad.c") in r["unreadable"], r["unreadable"]
        r = ws.search("初始化", max_results=1)
        assert len(r["hits"]) == 1 and r["stop"], r
        assert len(ws.search("uart_init", ignore_case=True)["hits"]) == 1
        assert len(ws.search(r"Temp_\w+", regex=True)["hits"]) == 1
        expect_error(lambda: ws.search("(", regex=True), "正则")
        r = ws.search("中文", folder="Function", exts=[".c"])
        assert {h[0] for h in r["hits"]} == {fn("mixed.c"), fn("data.c")}, r["hits"]

    def t_search_v12():
        # 1.2.0：默认跳过厂家库目录、按文件分组、压缩空白、默认 20 条、只列文件
        r = ws.search("厂家库")
        assert not r["hits"] and r["skipped_libs"] == ["Lib"], r
        r = ws.search("厂家库", folder="Lib")
        assert [h[0] for h in r["hits"]] == [os.path.join("Lib", "lib.c")] and not r["skipped_libs"], r
        r = ws.search("对齐")
        assert r["hits"] == [(fn("pad.c"), 1, "int x; /* 对齐 注释 */")], r["hits"]
        r = ws.search("// line")
        assert len(r["hits"]) == 20 and r["stop"], (len(r["hits"]), r["stop"])
        r = ws.search("初始化", files_only=True)
        assert r["files"] == [(fn("temp.c"), 1), (fn("uart.c"), 1)] and not r["hits"], r
        text = core._fmt_search(ws, ws.search("初始化"), "初始化")
        lines = text.split("\n")
        assert fn("temp.c") in lines and "  6: // 初始化 ADC" in lines, text
        assert "跳过了厂家库目录" in text, text
        text = core._fmt_search(ws, ws.search("初始化", files_only=True), "初始化")
        assert "只列文件" in text and "%s（1 处）" % fn("temp.c") in text, text

    def t_edit_gbk():
        old = read_bytes(p("Function\\temp.c"))
        r = ws.read_source("Function\\temp.c")
        pr = ws.prepare_edit("Function\\temp.c", [{"old": "    // 初始化 ADC", "new": "    // 初始化 ADC（12 位）"}],
                             r["sha256"], "自测：改注释")
        assert pr["ranges"] == [(6, 6)], pr["ranges"]
        assert read_bytes(p("Function\\temp.c")) == old, "prepare 不应该写盘"
        c = ws.commit(pr["edit_id"])
        want = old.replace("    // 初始化 ADC".encode("gbk"), "    // 初始化 ADC（12 位）".encode("gbk"))
        assert read_bytes(p("Function\\temp.c")) == want, "写回内容不对"
        assert c["backup"] and read_bytes(c["backup"]) == old, "备份不对"
        assert c["before"]["encrypted"] is False and c["after"]["encrypted"] is False, c
        expect_error(lambda: ws.commit(pr["edit_id"]), "不存在或已经用过")

    def t_multiline():
        pr = ws.prepare_edit("Function\\temp.c", [{"old": "void Temp_Init(void)\n{",
                                                   "new": "void Temp_Init(void)\n{\n    Temp_Reset();"}])
        ws.commit(pr["edit_id"])
        data = read_bytes(p("Function\\temp.c"))
        assert b"void Temp_Init(void)\r\n{\r\n    Temp_Reset();\r\n" in data, data
        assert b"\n" not in data.replace(b"\r\n", b""), "不应该出现单独的 LF"

    def t_mixed():
        pr = ws.prepare_edit("Function\\mixed.c", [{"old": "line2\nline3", "new": "line2\nline2b\nline3"},
                                                   {"old": "line4", "new": "line4x"}])
        ws.commit(pr["edit_id"])
        want = "line1\r\nline2\nline2b\nline3\nline4x\r\n// 中文\r\n".encode("gbk")
        assert read_bytes(p("Function\\mixed.c")) == want, read_bytes(p("Function\\mixed.c"))

    def t_match_rules():
        m = "Function\\mixed.c"
        expect_error(lambda: ws.prepare_edit(m, [{"old": "line", "new": "x"}]), "不止一次")
        expect_error(lambda: ws.prepare_edit(m, [{"old": "不存在的内容", "new": "x"}]), "没有找到")
        expect_error(lambda: ws.prepare_edit(m, [{"old": "line1\r\nline2", "new": "a"},
                                                 {"old": "line2\nline2b", "new": "b"}]), "重叠")
        expect_error(lambda: ws.prepare_edit(m, [{"old": "", "new": "x"}]), "不能为空")
        expect_error(lambda: ws.prepare_edit(m, [{"old": "line1", "new": "line1"}]), "完全一样")

    def t_line_edits():
        # 1.2.0：按行号修改。必须给 base_sha256，并核对行内容；行号都按修改前的文件算
        f = "Function\\lines.c"
        sha = ws.read_source(f)["sha256"]
        expect_error(lambda: ws.prepare_edit(f, [{"start_line": 2, "first_line": "int a2;", "new": "x"}]),
                     "必须提供 base_sha256")
        expect_error(lambda: ws.prepare_edit(f, [{"start_line": 2, "first_line": "int a3;", "new": "x"}], sha), "对不上")
        expect_error(lambda: ws.prepare_edit(f, [{"start_line": 2, "end_line": 3, "first_line": "int a2;", "new": "x"}],
                                             sha), "last_line")
        expect_error(lambda: ws.prepare_edit(f, [{"start_line": 9, "first_line": "x", "new": "x"}], sha), "行号范围不对")
        expect_error(lambda: ws.prepare_edit(f, [{"insert_after": 1, "after_line": "int a1;", "new": "x"},
                                                 {"insert_after": 1, "after_line": "int a1;", "new": "y"}], sha), "重叠")
        expect_error(lambda: ws.prepare_edit(f, [{"old": "int a1;", "start_line": 1, "first_line": "int a1;",
                                                  "new": "x"}], sha), "不能同时用")
        pr = ws.prepare_edit(f, [
            {"start_line": 2, "end_line": 3, "first_line": "  int   a2; ", "last_line": "int a3;",
             "new": "int b2;\nint b3;\nint b3x;"},
            {"insert_after": 4, "after_line": "int a4;", "new": "int c4;\n"},
            {"insert_after": 0, "new": "/* top */"},
            {"start_line": 5, "first_line": "int a5_with_a_long", "new": ""},
        ], sha)
        c = ws.commit(pr["edit_id"])
        want = "/* top */\r\nint a1;\r\nint b2;\r\nint b3;\r\nint b3x;\r\nint a4;\r\nint c4;\r\n"
        assert read_bytes(p(f)) == want.encode("gbk"), read_bytes(p(f))
        # commit_edit 返回完整 sha256，接着改同一个文件时直接用，不用重新读取
        assert c["sha256"] == core.sha256_hex(read_bytes(p(f))), c["sha256"]
        assert ("sha256：%s" % c["sha256"]) in core._fmt_commit(c), core._fmt_commit(c)
        pr = ws.prepare_edit(f, [{"start_line": 1, "first_line": "/* top */", "new": "/* top v2 */"}], c["sha256"])
        ws.commit(pr["edit_id"])
        assert read_bytes(p(f)).startswith(b"/* top v2 */\r\nint a1;\r\n"), read_bytes(p(f))
        # 最后一行没有换行的文件：插入、删除、替换后，文件末尾仍然没有换行
        g = "Function\\noeol.c"
        sha = ws.read_source(g)["sha256"]
        pr = ws.prepare_edit(g, [{"insert_after": 2, "after_line": "b = 2;", "new": "c = 3;"}], sha)
        c = ws.commit(pr["edit_id"])
        assert read_bytes(p(g)) == b"a = 1;\r\nb = 2;\r\nc = 3;", read_bytes(p(g))
        pr = ws.prepare_edit(g, [{"start_line": 3, "first_line": "c = 3;", "new": ""}], c["sha256"])
        c = ws.commit(pr["edit_id"])
        assert read_bytes(p(g)) == b"a = 1;\r\nb = 2;", read_bytes(p(g))
        pr = ws.prepare_edit(g, [{"start_line": 2, "first_line": "b = 2;", "new": "b = 22;"}], c["sha256"])
        ws.commit(pr["edit_id"])
        assert read_bytes(p(g)) == b"a = 1;\r\nb = 22;", read_bytes(p(g))

    def t_unencodable():
        expect_error(lambda: ws.prepare_edit("Function\\mixed.c", [{"old": "line1", "new": "line1 \u2705"}]),
                     "无法用 GBK")

    def t_ascii_to_gbk():
        pr = ws.prepare_edit("Function\\a.h", [{"old": "int a;", "new": "int a; // 计数"}])
        assert pr["enc_after"] == "GBK", pr["enc_after"]
        ws.commit(pr["edit_id"])
        assert read_bytes(p("Function\\a.h")) == ASCII_TEXT.replace("int a;", "int a; // 计数").encode("gbk")
        assert ws.read_source("Function\\a.h")["encoding"] == "GBK"

    def t_doc_utf8():
        # 1.3.0：文档类文件 GBK 存得下时保持 GBK，存不了时整份改存 UTF-8 并在 diff 文件里注明；纯英文的加中文直接存 UTF-8
        g = "Function\\notes.md"
        pr = ws.prepare_edit(g, [{"old": "参数", "new": "参数表"}])
        assert pr["enc_after"] == "GBK", pr["enc_after"]
        ws.commit(pr["edit_id"])
        out = preview(ws, "prepare_edit", {"path": g, "edits": [{"old": "频率", "new": "频率 10 µs ✅"}]})
        lines = out.split("\n")
        assert "编码：GBK → UTF-8" in lines, out
        eid = [s for s in lines if s.startswith("修改编号：")][0].split("：", 1)[1]
        path = [s for s in lines if s.startswith("diff 已保存给项目负责人查看")][0].split("：", 1)[1]
        with open(path, encoding="utf-8-sig") as fh:
            assert "编码：GBK → UTF-8" in fh.read()
        ws.commit(eid)
        want = DOC_TEXT.replace("参数", "参数表").replace("频率", "频率 10 µs ✅")
        assert read_bytes(p(g)) == want.encode("utf-8"), read_bytes(p(g))
        assert ws.read_source(g)["encoding"] == "UTF-8"
        pr = ws.prepare_edit("Function\\readme.txt", [{"old": "Readme", "new": "Readme 说明"}])
        assert pr["enc_after"] == "UTF-8", pr["enc_after"]
        ws.commit(pr["edit_id"])
        assert read_bytes(p("Function\\readme.txt")) == "Readme 说明\r\n".encode("utf-8")

    def t_doc_new_file():
        # 1.3.0：文档类新文件用 UTF-8；其他新文件仍用 GBK，GBK 存不了的字符照样报错
        pr = ws.prepare_new_file("Function\\todo.md", "# 待办\n- 频率 10 µs\n")
        assert pr["encoding"] == "UTF-8", pr["encoding"]
        ws.commit(pr["edit_id"])
        assert read_bytes(p("Function\\todo.md")) == "# 待办\r\n- 频率 10 µs\r\n".encode("utf-8")
        expect_error(lambda: ws.prepare_new_file("Function\\todo.c", "// 10 µs\n"), "无法用 GBK")

    def t_bom():
        pr = ws.prepare_edit("Function\\data.c", [{"old": "int g_data = 0;", "new": "int g_data = 1; // 改过"}])
        ws.commit(pr["edit_id"])
        want = codecs.BOM_UTF8 + BOM_TEXT.replace("int g_data = 0;", "int g_data = 1; // 改过").encode("utf-8")
        assert read_bytes(p("Function\\data.c")) == want

    def t_utf8():
        pr = ws.prepare_edit("Function\\uart.c", [{"old": "// 初始化串口", "new": "// 初始化串口（115200）"}])
        ws.commit(pr["edit_id"])
        want = UTF8_TEXT.replace("// 初始化串口", "// 初始化串口（115200）").encode("utf-8")
        assert read_bytes(p("Function\\uart.c")) == want

    def t_stale():
        r = ws.read_source("Function\\uart.c")
        pr = ws.prepare_edit("Function\\uart.c", [{"old": "void Uart_Init(void)", "new": "void Uart_Init(int baud)"}],
                             r["sha256"])
        with open(p("Function\\uart.c"), "ab") as f:
            f.write(b"// x\n")
        expect_error(lambda: ws.commit(pr["edit_id"]), "被改过")
        assert not ws.lock_reason(), "文件被改过只应该拒绝，不应该锁定"
        expect_error(lambda: ws.prepare_edit("Function\\uart.c", [{"old": "void Uart_Init(void)", "new": "x"}],
                                             r["sha256"]), "变了")

    def t_protected():
        expect_error(lambda: ws.prepare_edit("Project.uvprojx", [{"old": "<Project>", "new": "<P>"}]), "Keil 工程文件")
        assert "Project" in ws.read_source("Project.uvprojx")["body"]

    def t_new_file():
        pr = ws.prepare_new_file("Function\\new_module.c", "/* 新模块 */\nvoid New_Init(void);\n", "自测：新建")
        assert pr["mode"] == "create", pr["mode"]
        c = ws.commit(pr["edit_id"])
        assert read_bytes(p("Function\\new_module.c")) == "/* 新模块 */\r\nvoid New_Init(void);\r\n".encode("gbk")
        assert c["before"] is None and c["backup"] is None, c
        expect_error(lambda: ws.prepare_new_file("Function\\new_module.c", "x"), "已存在且有内容")
        pr = ws.prepare_new_file("Function\\empty.c", "int e;\n")
        assert pr["mode"] == "fill_empty", pr["mode"]
        ws.commit(pr["edit_id"])
        assert read_bytes(p("Function\\empty.c")) == b"int e;\r\n"
        expect_error(lambda: ws.prepare_new_file("NoSuchDir\\x.c", "x"), "上级文件夹不存在")

    def t_review_file():
        # 1.2.0：diff 默认写成文件给项目负责人看，不返回给 AI；diff 上下文 1 行；show_diff 时也返回；打开失败只提示
        f = "Function\\long.c"
        out = preview(ws, "prepare_edit", {"path": f, "note": "自测：diff 文件",
                                       "edits": [{"old": "// line 200", "new": "// line 200x"}]})
        assert "```diff" not in out and "+1 -1" in out, out
        line = [s for s in out.split("\n") if s.startswith("diff 已保存给项目负责人查看")]
        assert line, out
        path = line[0].split("：", 1)[1]
        assert os.path.isfile(path) and os.path.dirname(os.path.dirname(path)) == os.path.join(backups, "diffs"), path
        with open(path, encoding="utf-8-sig") as fh:
            body = fh.read()
        assert "修改编号" in body and "自测：diff 文件" in body, body
        assert "-// line 200\n+// line 200x" in body and " // line 199\n" in body and " // line 198" not in body, body
        out = preview(ws, "prepare_edit", {"path": f, "show_diff": True,
                                       "edits": [{"old": "// line 300", "new": "// line 300x"}]})
        assert "```diff" in out and "-// line 300" in out and "diff 已保存给项目负责人查看" in out, out
        ws.cfg["diff_viewer"] = os.path.join(base, "no_such_viewer.exe")
        try:
            out = preview(ws, "prepare_new_file", {"path": "Function\\review_new.c", "content": "int r;\n"})
        finally:
            ws.cfg["diff_viewer"] = ""
        assert "内容已保存给项目负责人查看" in out and "打开 diff 文件失败" in out and "预览" not in out, out
        assert not os.path.exists(p("Function\\review_new.c")), "prepare_new_file 不应该写盘"
        w = core.Workspace(proj, "自测", cfg=dict(cfg, diff_to_file=False))
        out = preview(w, "prepare_edit", {"path": f, "edits": [{"old": "// line 100", "new": "// line 100x"}]})
        assert "```diff" in out and "已保存" not in out, out

    def t_whitelist_root():
        # 白名单固定为配置的文件夹，会话文件夹只当工作文件夹
        other_dir = os.path.join(base, "other")
        os.makedirs(other_dir, exist_ok=True)
        other = os.path.join(other_dir, "x.c")
        with open(other, "wb") as f:
            f.write("int x; // 其他项目\r\n".encode("gbk"))
        w = core.Workspace(proj, "测试会话", cfg=dict(cfg2))
        assert w.root == os.path.realpath(base) and w.base == os.path.realpath(proj), (w.root, w.base)
        assert w.resolve("Function\\temp.c")[1] == fn("temp.c")
        real, shown = w.resolve(other)
        assert shown == real == os.path.realpath(other), (real, shown)
        expect_error(lambda: w.resolve(os.path.join(tempfile.gettempdir(), "nope.c"), must_exist=False), "不在白名单")
        expect_error(lambda: w.resolve(os.path.join(backups, "x.c"), must_exist=False), "排除目录")
        w2 = core.Workspace(tempfile.gettempdir(), "测试会话", cfg=dict(cfg2))
        assert w2.base == w2.root == os.path.realpath(base), (w2.root, w2.base)
        pr = w.prepare_edit(other, [{"old": "int x;", "new": "int x = 1;"}], note="自测：工作文件夹外的文件")
        c = w.commit(pr["edit_id"])
        assert read_bytes(other) == "int x = 1; // 其他项目\r\n".encode("gbk")
        assert c["backup"].endswith(os.path.join("other", "x.c")), c["backup"]
        assert not w.search("其他项目")["hits"], "不指定 folder 时只应该搜工作文件夹"
        assert w.search("其他项目", folder=other_dir)["hits"], "指定白名单里的完整路径应该能搜到"
        _, entries = w.change_log()
        assert [e["path"] for e in entries] == [os.path.realpath(other)], entries
        if os.path.isdir("E:\\"):
            c3 = dict(cfg)
            c3["whitelist_root"] = "E:\\"
            assert core.Workspace(proj, "t", cfg=c3).root.upper() == "E:\\"
        c4 = dict(cfg)
        c4["whitelist_root"] = os.path.splitdrive(os.path.expanduser("~"))[0] + "\\"
        expect_error(lambda: core.Workspace(proj, "t", cfg=c4), "用户目录")

    def t_tool_text():
        assert os.path.realpath(proj).lower() in ws.tool("get_status", {}).lower()
        assert "第 1–3 行" in core._fmt_read(ws.read_source("Function\\temp.c", "1", "3"))
        assert "use_safe_edit: false" in ws.tool("read_source", {"path": "Function\\temp.c"})
        assert "找到" in ws.tool("search_code", {"pattern": "初始化", "exts": ".c,.h"})
        expect_error(lambda: ws.tool("nope", {}), "没有这个工具")

    def t_encrypted():
        sample = os.path.realpath(a.sample)
        assert os.path.isfile(sample), "样本文件不存在：%s" % sample
        ps = cfg["powershell"]

        def raw_sha(path):
            r = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", core._PS_STATE],
                               env=dict(os.environ, SE_SRC=path), capture_output=True)
            assert r.returncode == 0, r.stderr.decode("gbk", "replace")
            return r.stdout.decode("ascii").split()[1].lower()

        sample_before = raw_sha(sample)
        dst = p("Function\\enc_sample.h")
        r = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command",
                            "[System.IO.File]::Copy($env:SE_SRC, $env:SE_DST, $false)"],
                           env=dict(os.environ, SE_SRC=sample, SE_DST=dst), capture_output=True)
        assert r.returncode == 0, r.stderr.decode("gbk", "replace")
        assert raw_sha(dst) != core.sha256_hex(read_bytes(dst)), "样本文件看起来没有加密（两边读到的一样），请换一个加密文件"
        core.write_in_place(dst, "/* 加密写回测试：假数据 */\r\nint g_dummy = 0;\r\n".encode("gbk"))
        assert ws._disk_state(dst, core.sha256_hex(read_bytes(dst)))["encrypted"], "原地写入后应该仍然加密"
        target = "Function\\enc_sample.h"
        assert ws.check_file(target)["use_safe_edit"] is True
        out = ws.tool("prepare_edit", {"path": target,
                                      "edits": [{"old": "g_dummy = 0", "new": "g_dummy = 1"}]})
        assert "写回成功" in out and "已打开" not in out, out
        assert out.count(dst) == 1 and "修改编号：" not in out and "diff 已保存" not in out, out
        assert "内容核对：通过" in out and "已加密→已加密" in out and "编号：" in out, out
        digest = next(line.split("：", 1)[1] for line in out.splitlines() if line.startswith("sha256："))
        assert digest == core.sha256_hex(read_bytes(dst))
        assert b"g_dummy = 1" in read_bytes(dst)
        assert ws.last_edit_id not in ws.pending, "默认修改不应留下待确认操作"
        backup = next(line.split("：", 1)[1] for line in out.splitlines() if line.startswith("备份："))
        assert ws._disk_state(dst, core.sha256_hex(read_bytes(dst)))["encrypted"]
        assert ws._disk_state(backup, core.sha256_hex(read_bytes(backup)))["encrypted"]
        # 只有明确 dry_run 才不写盘，之后可以直接 commit，不再要求用户逐次确认。
        out = ws.tool("prepare_edit", {"path": target, "dry_run": True, "base_sha256": digest,
                                      "edits": [{"old": "g_dummy = 1", "new": "g_dummy = 2"}]})
        assert "没有写盘" in out and b"g_dummy = 1" in read_bytes(dst), out
        out = ws.tool("commit_edit", {"edit_id": ws.last_edit_id})
        assert "写回成功" in out and b"g_dummy = 2" in read_bytes(dst)
        out = ws.tool("prepare_edit", {"path": target, "show_diff": True,
                                      "edits": [{"old": "g_dummy = 2", "new": "g_dummy = 20"}]})
        assert "写回成功" in out and "```diff" in out and b"g_dummy = 20" in read_bytes(dst), out
        batch = ws.tool("check_file", {"paths": [target, "Function\\temp.c"]})
        assert len(batch.splitlines()) == 2 and "use_safe_edit: true" in batch and "use_safe_edit: false" in batch
        # 差异文件留档失败仍提示并回传差异，不因精简结果丢失警告。
        original_review_writer = ws._write_review

        def unavailable_review(*args):
            raise OSError("模拟 diff 留档失败")

        ws._write_review = unavailable_review
        try:
            out = ws.tool("prepare_edit", {"path": target,
                                          "edits": [{"old": "g_dummy = 20", "new": "g_dummy = 21"}]})
        finally:
            ws._write_review = original_review_writer
        assert "写回成功" in out and "diff 文件写不了" in out and "```diff" in out, out
        found = ws.search("g_dummy", encrypted_only=True)
        assert {h[0] for h in found["hits"]} == {fn("enc_sample.h")}, found
        assert found["skipped_plain"], found
        # 已有的加密空文件使用同一个默认直接写回入口。
        core.write_in_place(dst, b"")
        assert ws.check_file(target)["encrypted"] is True
        out = ws.tool("prepare_new_file", {"path": target, "content": "int g_dummy = 3;\n"})
        assert "写回成功" in out and b"g_dummy = 3" in read_bytes(dst), out
        assert ws.check_file(target)["encrypted"] is True
        assert raw_sha(sample) == sample_before, "原样本文件不应该有任何变化"

    def t_plain_routing():
        w = core.Workspace(proj, "加密分流", cfg=dict(cfg))
        target = "Function\\temp.c"
        before = read_bytes(p(target))
        route = w.check_file(target)
        assert route["exists"] and not route["encrypted"] and not route["use_safe_edit"], route
        assert "use_safe_edit: false" in w.tool("check_file", {"path": target})
        out = w.tool("prepare_edit", {"path": target,
                                     "edits": [{"old": "ADC_Init();", "new": "ADC_Init(); // skipped"}]})
        assert "use_safe_edit: false" in out and "修改编号：" not in out, out
        assert read_bytes(p(target)) == before and not w.pending
        missing = "Function\\plain_new_v14.c"
        out = w.tool("prepare_new_file", {"path": missing, "content": "int plain;\n"})
        assert "文件不存在" in out and "use_safe_edit: false" in out, out
        assert not os.path.exists(p(missing)) and not w.pending
        expect_error(lambda: w.check_file("secret\\key.c"), "AI 不许读")
        expect_error(lambda: w.check_file("..\\config_test.json"), "不在白名单")

    def t_batch_check():
        w = core.Workspace(proj, "批量加密检测", cfg=dict(cfg))
        paths = ["Function\\temp.c", "Function\\uart.c", "Function\\missing_v15.c"]
        before = [read_bytes(p(path)) for path in paths[:2]]
        out = w.tool("check_file", {"paths": paths})
        lines = out.splitlines()
        assert len(lines) == 3 and all("use_safe_edit: false" in line for line in lines), out
        assert "GBK" in lines[0] and "UTF-8" in lines[1] and "文件不存在" in lines[2], out
        assert "sha256" not in out and "处理方式" not in out and "g_data" not in out, out
        assert [read_bytes(p(path)) for path in paths[:2]] == before
        assert not os.path.exists(p(paths[2])) and not w.pending
        for args in ({}, {"path": paths[0], "paths": paths}):
            expect_error(lambda: w.tool("check_file", args), "必须且只能")
        for paths_arg in ([], "bad", [paths[0]] * (core.MAX_CHECK_FILES + 1)):
            expect_error(lambda: w.tool("check_file", {"paths": paths_arg}), "1–50")
        for paths_arg in ([""], [None], [paths[0], 3]):
            expect_error(lambda: w.tool("check_file", {"paths": paths_arg}), "非空字符串")
        expect_error(lambda: w.tool("check_file", {"paths": [paths[0], "secret\\key.c"]}), "AI 不许读")
        expect_error(lambda: w.tool("check_file", {"paths": [paths[0], "..\\config_test.json"]}), "不在白名单")

    def t_unknown_routing():
        w = core.Workspace(proj, "检测失败", cfg=dict(cfg))
        target = "Function\\temp.c"
        before = read_bytes(p(target))

        def unavailable(*args):
            raise core.WriteFailure("模拟检测不可用")

        w._disk_state = unavailable
        expect_error(lambda: w.tool("prepare_edit", {"path": target,
                     "edits": [{"old": "ADC_Init();", "new": "changed();"}]}), "无法确定加密状态")
        expect_error(lambda: w.tool("check_file", {"paths": [target]}), "无法确定加密状态")
        assert read_bytes(p(target)) == before and not w.pending

    def t_lock():
        pr = ws.prepare_edit("Function\\uart.c", [{"old": "void Uart_Init(void)",
                                                   "new": "void Uart_Init(void) /* lock test */"}])
        real_write = core.write_in_place
        core.write_in_place = lambda path, data: real_write(path, data + b"// broken\r\n")
        try:
            expect_error(lambda: ws.commit(pr["edit_id"]), "工具已锁定", core.WriteFailure)
        finally:
            core.write_in_place = real_write
        assert ws.lock_reason() and os.path.isfile(ws.lock_path), "应该已经锁定"
        expect_error(lambda: ws.prepare_edit("Function\\uart.c", [{"old": "void", "new": "v"}]), "已锁定")
        assert ws.read_source("Function\\uart.c")["total"] > 0, "锁定时应该仍然可以读"
        os.remove(ws.lock_path)
        assert not ws.lock_reason(), "删除锁文件后应该解锁"

    def t_change_log():
        _, entries = ws.change_log()
        files = {e["file"] for e in entries}
        assert fn("temp.c") in files and fn("new_module.c") in files, files
        text = ws.tool("change_log", {})
        assert "自测：改注释" in text and "失败" in text, text

    def env_for_child():
        env = dict(os.environ, SAFE_EDIT_CONFIG=cfg_file)
        env.pop("SAFE_EDIT_ROOT", None)
        env.pop("REASONIX_WORKSPACE_ROOT", None)
        return env

    def t_mcp_reasonix_env():
        # Reasonix 启动插件时提供 REASONIX_WORKSPACE_ROOT：服务应该用它当白名单（启动目录故意设成别的文件夹）
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "selftest-reasonix", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_status", "arguments": {}}},
        ]
        env = env_for_child()
        env["REASONIX_WORKSPACE_ROOT"] = proj
        data = "".join(json.dumps(m, ensure_ascii=False) + "\n" for m in msgs).encode("utf-8")
        r = subprocess.run([sys.executable, os.path.join(HERE, "safe_edit_server.py")], input=data, cwd=base,
                           env=env, capture_output=True, timeout=120)
        lines = [json.loads(s) for s in r.stdout.decode("utf-8").splitlines()]
        status = [m for m in lines if m.get("id") == 2][0]["result"]["content"][0]["text"]
        assert "REASONIX_WORKSPACE_ROOT" in status and os.path.realpath(proj).lower() in status.lower(), status

    def t_mcp_server():
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "selftest", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get_status", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "read_source", "arguments": {"path": "Function\\temp.c", "end_line": 2}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
             "params": {"name": "read_source", "arguments": {"path": "..\\config_test.json"}}},
            {"jsonrpc": "2.0", "id": 6, "method": "nope"},
        ]
        data = "".join(json.dumps(m, ensure_ascii=False) + "\n" for m in msgs).encode("utf-8")
        r = subprocess.run([sys.executable, os.path.join(HERE, "safe_edit_server.py")], input=data, cwd=proj,
                           env=env_for_child(), capture_output=True, timeout=120)
        out = {}
        for line in r.stdout.decode("utf-8").splitlines():
            msg = json.loads(line)
            out[msg.get("id")] = msg
        assert out[1]["result"]["protocolVersion"] == "2025-06-18", out.get(1)
        assert len(out[2]["result"]["tools"]) == 8, out.get(2)
        schemas = {t["name"]: t for t in out[2]["result"]["tools"]}
        assert "check_file" in schemas
        check_schema = schemas["check_file"]["inputSchema"]
        assert check_schema["properties"]["paths"]["maxItems"] == core.MAX_CHECK_FILES
        assert check_schema["oneOf"] == [{"required": ["path"]}, {"required": ["paths"]}]
        assert schemas["prepare_edit"]["annotations"]["readOnlyHint"] is False
        assert "dry_run" in schemas["prepare_edit"]["inputSchema"]["properties"]
        status = out[3]["result"]["content"][0]["text"]
        assert os.path.realpath(proj).lower() in status.lower() and "启动时的当前目录" in status, status
        assert out[4]["result"]["isError"] is False and "GBK" in out[4]["result"]["content"][0]["text"], out.get(4)
        assert out[5]["result"]["isError"] is True, out.get(5)
        assert out[6]["error"]["code"] == -32601, out.get(6)

    def t_mcp_roots():
        # 客户端声明支持 roots：服务应该向客户端要 roots，并用它当白名单（启动目录故意设成别的文件夹）
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {"roots": {"listChanged": False}},
                        "clientInfo": {"name": "selftest-roots", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": "safe-edit-roots-1",
             "result": {"roots": [{"uri": pathlib.Path(proj).as_uri(), "name": "proj"}]}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_status", "arguments": {}}},
        ]
        data = "".join(json.dumps(m, ensure_ascii=False) + "\n" for m in msgs).encode("utf-8")
        r = subprocess.run([sys.executable, os.path.join(HERE, "safe_edit_server.py")], input=data, cwd=base,
                           env=env_for_child(), capture_output=True, timeout=120)
        lines = [json.loads(s) for s in r.stdout.decode("utf-8").splitlines()]
        assert any(m.get("method") == "roots/list" for m in lines), "服务没有向客户端要 roots"
        status = [m for m in lines if m.get("id") == 2][0]["result"]["content"][0]["text"]
        assert "客户端提供的 roots" in status and os.path.realpath(proj).lower() in status.lower(), status

    def t_mcp_whitelist_root():
        # 配置了 whitelist_root，同时 Reasonix 提供了工作区：白名单用配置，工作文件夹用 Reasonix 的
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "selftest-whitelist", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_status", "arguments": {}}},
        ]
        env = env_for_child()
        env["SAFE_EDIT_CONFIG"] = cfg2_file
        env["REASONIX_WORKSPACE_ROOT"] = proj
        data = "".join(json.dumps(m, ensure_ascii=False) + "\n" for m in msgs).encode("utf-8")
        r = subprocess.run([sys.executable, os.path.join(HERE, "safe_edit_server.py")], input=data, cwd=base,
                           env=env, capture_output=True, timeout=120)
        lines = [json.loads(s) for s in r.stdout.decode("utf-8").splitlines()]
        status = [m for m in lines if m.get("id") == 2][0]["result"]["content"][0]["text"]
        assert "配置文件 whitelist_root" in status and os.path.realpath(base).lower() in status.lower() \
            and os.path.realpath(proj).lower() in status.lower(), status
        # 命令行的 --root 只决定工作文件夹，不能读白名单外的文件
        env = env_for_child()
        env["SAFE_EDIT_CONFIG"] = cfg2_file
        r = subprocess.run([sys.executable, os.path.join(HERE, "safe_edit_cli.py"), "--root", proj, "read",
                            r"C:\Windows\win.ini"], env=env, capture_output=True, timeout=120)
        out = r.stdout.decode("utf-8", "replace")
        assert r.returncode == 1 and "不在白名单" in out, out

    def t_cli():
        cli = os.path.join(HERE, "safe_edit_cli.py")

        def run(args, spec=None):
            r = subprocess.run([sys.executable, cli, "--root", proj] + args, env=env_for_child(), capture_output=True,
                               input=json.dumps(spec, ensure_ascii=False).encode("utf-8") if spec else None,
                               timeout=120)
            return r.returncode, r.stdout.decode("utf-8", "replace")

        code, out = run(["read", "Function\\temp.c", "--end", "2"])
        assert code == 0 and "GBK" in out, out
        code, out = run(["search", "初始化", "--files-only"])
        assert code == 0 and "只列文件" in out, out
        spec = {"path": "Function\\temp.c", "note": "自测：命令行",
                "edits": [{"old": "ADC_Init();", "new": "ADC_Init(); // 命令行改的"}]}
        code, out = run(["apply", "--spec", "-", "--dry-run"], spec)
        assert code == 0 and "use_safe_edit: false" in out and "修改编号：" not in out, out
        assert "命令行改的".encode("gbk") not in read_bytes(p("Function\\temp.c")), "--dry-run 不应该写盘"
        code, out = run(["apply", "--spec", "-"], spec)
        assert code == 0 and "use_safe_edit: false" in out and "写回成功" not in out, out
        assert "命令行改的".encode("gbk") not in read_bytes(p("Function\\temp.c"))
        code, out = run(["check", "Function\\temp.c"])
        assert code == 0 and "明文" in out and len(out.splitlines()) == 1, out
        code, out = run(["check", "Function\\temp.c", "Function\\uart.c"])
        assert code == 0 and len(out.splitlines()) == 2 and out.count("use_safe_edit: false") == 2, out
        code, out = run(["read", "..\\config_test.json"])
        assert code == 1, out

    tests = [
        ("白名单检查", t_root), ("路径检查", t_paths), ("识别编码和行尾", t_read_encodings),
        ("按行读取和行数上限", t_read_range), ("搜索（GBK 和 UTF-8 里的中文）", t_search),
        ("搜索：跳过厂家库、按文件分组、压缩空白、只列文件", t_search_v12),
        ("GBK 文件修改、写回、备份", t_edit_gbk), ("多行修改沿用 CRLF", t_multiline),
        ("混合行尾文件只改动命中的部分", t_mixed), ("恰好一次、重叠、空内容等规则", t_match_rules),
        ("按行号修改，commit_edit 返回的 sha256 可以直接接着用", t_line_edits),
        ("GBK 表示不了的字符会报错", t_unencodable), ("纯英文文件加中文后按 GBK 保存", t_ascii_to_gbk),
        ("文档类文件：GBK 存不了的字符整份改存 UTF-8", t_doc_utf8), ("文档类新文件用 UTF-8", t_doc_new_file),
        ("UTF-8 带 BOM 文件保持 BOM", t_bom), ("UTF-8 文件保持 UTF-8", t_utf8),
        ("准备之后文件被改过会拒绝写回", t_stale), ("Keil 工程文件不允许修改", t_protected),
        ("新建文件和写入空文件", t_new_file), ("diff 写成文件给项目负责人看", t_review_file),
        ("白名单固定为配置文件夹、会话文件夹只当工作文件夹", t_whitelist_root),
        ("工具输出文字", t_tool_text),
        ("明文和不存在的文件跳过 safe_edit，路径权限仍有效", t_plain_routing),
        ("检测失败不能当作明文继续", t_unknown_routing),
        ("批量检测简短结果、输入边界和访问限制", t_batch_check),
    ]
    if a.sample:
        tests.append(("加密文件写回后仍然加密、备份仍然加密", t_encrypted))
    tests += [("写回出错时锁定，删除锁文件后解锁", t_lock), ("修改记录", t_change_log),
              ("MCP 服务（子进程）", t_mcp_server), ("MCP 服务从客户端取 roots 当白名单", t_mcp_roots),
              ("MCP 服务用 Reasonix 提供的项目文件夹当白名单", t_mcp_reasonix_env),
              ("配置了白名单时：服务和命令行都不能越出白名单", t_mcp_whitelist_root),
              ("命令行（子进程）", t_cli)]
    for name, func in tests:
        check(name, func)

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print("\n共 %d 项：通过 %d 项，失败 %d 项" % (len(RESULTS), passed, len(RESULTS) - passed))
    if not a.sample:
        print("没有给 --sample，跳过了加密文件测试。")
    if a.keep:
        print("测试文件夹已保留：%s" % base)
    else:
        try:
            shutil.rmtree(base)
            print("测试文件夹已删除：%s" % base)
        except OSError as e:
            print("测试文件夹没删干净，请手动删除：%s（%s）" % (base, e))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
