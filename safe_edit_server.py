# -*- coding: utf-8 -*-
"""safe_edit 的 MCP 服务：标准输入输出，JSON-RPC 2.0，每行一条消息。

由 Claude Code、Codex 等 MCP 客户端启动，必须用受信任的 Python 运行：
    C:\\Users\\Administrator\\AppData\\Local\\Programs\\Python\\Python312\\python.exe safe_edit_server.py

白名单文件夹的确定顺序：环境变量 SAFE_EDIT_ROOT > REASONIX_WORKSPACE_ROOT（Reasonix 提供）> 客户端提供的 roots > 启动时的当前目录。
只用 Python 标准库。stdout 只输出协议消息，日志写到 stderr。
"""

import json
import os
import queue
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import safe_edit_core as core  # noqa: E402

SUPPORTED_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
# 按顺序检查的环境变量：SAFE_EDIT_ROOT 由用户指定；REASONIX_WORKSPACE_ROOT 由 Reasonix 启动插件时提供
ROOT_ENV_VARS = ["SAFE_EDIT_ROOT", "REASONIX_WORKSPACE_ROOT"]
SERVER_INFO = {"name": "safe_edit", "version": core.VERSION}
ROOTS_TIMEOUT_S = 5.0

INSTRUCTIONS = (
    "先 get_status 确认范围与锁状态，再 check_file（可批量）。明文或不存在的文件用普通工具，保留编码和行尾；"
    "仅加密文件使用本服务，禁止其他工具改写。项目不在工作目录时用完整路径。"
    "只读所需行；仅在已授权范围内修改，默认直接写回、diff 留档，无需再次确认。"
    "用户要求预览才用 dry_run=true，随后 commit_edit；默认写回后不要重复提交。"
    "复用写回的 sha256。检测未知、报错或锁定时停止并报告，不得绕过。"
)


_S = {"type": "string"}
_B = {"type": "boolean"}
_I = {"type": "integer"}

TOOLS = [
    {
        "name": "get_status",
        "description": "任务开始时查看白名单、工作目录、锁状态及备份位置。",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "check_file",
        "description": "检测加密状态，不返回源码。path 或 paths 二选一；批量每文件一行。use_safe_edit=false 时用普通工具；任一检测失败则整批停止。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": dict(_S, description="单个文件路径"),
                "paths": {"type": "array", "items": _S, "minItems": 1, "maxItems": core.MAX_CHECK_FILES,
                          "description": "批量路径，最多 50 个"},
            },
            "oneOf": [{"required": ["path"]}, {"required": ["paths"]}],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "search_code",
        "description": "仅搜索加密文件，支持 GBK/UTF-8。默认 .c/.h，跳过输出和厂家库目录；folder 可指定库目录。返回行号及缩略内容，修改前按命中范围 read_source。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": dict(_S, description="关键词；默认普通文字"),
                "regex": dict(_B, description="启用正则，默认 false"),
                "folder": dict(_S, description="搜索目录，省略则为工作目录"),
                "exts": {"type": "array", "items": _S, "description": "扩展名，默认 .c/.h"},
                "ignore_case": dict(_B, description="忽略大小写，默认 false"),
                "max_results": dict(_I, description="结果上限，默认 20；files_only 时按文件计"),
                "files_only": dict(_B, description="仅列命中文件及数量，默认 false"),
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "read_source",
        "description": "按行读取加密源码，返回编码、行尾和 sha256。先按搜索命中指定范围；省略 end_line 默认 40 行，最多 300 行。行号及其制表符不是源码。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": dict(_S, description="文件路径"),
                "start_line": dict(_I, description="起始行，默认 1"),
                "end_line": dict(_I, description="结束行（含）；省略时读 40 行，最多 300 行"),
            },
            "required": ["path"],
        },
    },
    {
        "name": "prepare_edit",
        "description": "修改加密文件，默认直接写回并返回新 sha256；dry_run=true 才只预览。旧内容须唯一，或按修改前行号及锚点定位。保持编码/行尾；文档中 GBK 无法表示的字符按既有策略转 UTF-8。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": dict(_S, description="文件路径"),
                "edits": {
                    "type": "array",
                    "description": "最多 20 组，不得重叠；每组在 old 替换、整行替换、插入中选一种",
                    "items": {
                        "type": "object",
                        "properties": {
                            "old": dict(_S, description="旧内容，必须恰好出现一次"),
                            "new": dict(_S, description="新内容；空字符串为删除；换行写 \\n"),
                            "start_line": dict(_I, description="整行替换的首行（1 起）"),
                            "end_line": dict(_I, description="末行（含），默认同 start_line"),
                            "first_line": dict(_S, description="首行内容，整行替换必填；忽略空白，可用至少 10 字符的前缀"),
                            "last_line": dict(_S, description="末行内容，多行替换必填；锚点规则同 first_line"),
                            "insert_after": dict(_I, description="在此行后插入，0 为文件开头"),
                            "after_line": dict(_S, description="插入点行内容，非 0 插入必填；锚点规则同 first_line"),
                        },
                        "required": ["new"],
                    },
                },
                "base_sha256": dict(_S, description="读取或上次写回的 sha256；按行号修改必填"),
                "note": dict(_S, description="修改目的，记录到日志"),
                "dry_run": dict(_B, description="true 仅预览；默认 false 直接写回"),
                "show_diff": dict(_B, description="返回 diff，默认 false；不影响是否写回"),
            },
            "required": ["path", "edits"],
        },
    },
    {
        "name": "prepare_new_file",
        "description": "仅填充已有加密空文件，默认直接写回；文档 UTF-8、其他 GBK，CRLF、无 BOM。明文或不存在目标改用普通工具。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": dict(_S, description="已有加密空文件的路径"),
                "content": dict(_S, description="文件内容，换行写 \\n 即可"),
                "note": dict(_S, description="写入目的"),
                "dry_run": dict(_B, description="true 仅预览；默认 false 直接写回"),
                "show_diff": dict(_B, description="返回前 20 行预览，默认 false；不影响是否写回"),
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "commit_edit",
        "description": "提交 dry_run 留下的修改，备份后写回并核对内容和加密状态；返回新 sha256。失败会锁定。",
        "inputSchema": {
            "type": "object",
            "properties": {"edit_id": dict(_S, description="预览返回的修改编号")},
            "required": ["edit_id"],
        },
    },
    {
        "name": "change_log",
        "description": "列出修改文件、行号、目的、结果和备份，不含源码。",
        "inputSchema": {
            "type": "object",
            "properties": {"since": dict(_S, description="起始时间，如 2026-10-19 15:30；默认本会话")},
        },
    },
]
# 修改接口会写盘，明确向客户端标注，不能伪装为只读工具。
for _tool in TOOLS:
    if _tool["name"] in {"prepare_edit", "prepare_new_file", "commit_edit"}:
        _tool["annotations"] = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False}
TOOL_NAMES = {t["name"] for t in TOOLS}


def log(msg):
    """日志写到 stderr（客户端一般会记到自己的日志里），不能写 stdout。"""
    try:
        sys.stderr.buffer.write(("[safe_edit] %s\n" % msg).encode("utf-8", "replace"))
        sys.stderr.buffer.flush()
    except Exception:
        pass


def uri_to_path(uri):
    """file:///E:/soft/... → E:\\soft\\...；不是本机文件路径时返回 None。"""
    if not isinstance(uri, str) or not uri.lower().startswith("file:"):
        return None
    parsed = urllib.parse.urlparse(uri)
    if parsed.netloc and parsed.netloc.lower() != "localhost":
        return None
    path = urllib.request.url2pathname(parsed.path)
    return path or None


def text_result(text, error=False):
    return {"content": [{"type": "text", "text": text}], "isError": bool(error)}


class Server:
    def __init__(self):
        self.inbox = queue.Queue()
        self.backlog = []
        self.out_lock = threading.Lock()
        self.client_caps = {}
        self.client_name = ""
        self.ws = None
        self.ws_error = None
        self.request_seq = 0

    # ---- 收发

    def reader(self):
        stdin = sys.stdin.buffer
        while True:
            line = stdin.readline()
            if not line:
                self.inbox.put(None)
                return
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as e:
                self.send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error: %s" % e}})
                continue
            self.inbox.put(msg)

    def send(self, msg):
        data = json.dumps(msg, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
        with self.out_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    def next_message(self):
        if self.backlog:
            return self.backlog.pop(0)
        return self.inbox.get()

    def run(self):
        threading.Thread(target=self.reader, daemon=True).start()
        while True:
            msg = self.next_message()
            if msg is None:
                return
            for m in (msg if isinstance(msg, list) else [msg]):
                self.handle(m)

    # ---- 处理

    def handle(self, msg):
        if not isinstance(msg, dict):
            return
        method, mid = msg.get("method"), msg.get("id")
        if method is None:
            return  # 客户端发来的响应，没人在等，忽略
        if mid is None:
            if method == "notifications/initialized" and self.ws is None and self.ws_error is None:
                self.setup_workspace()
            return
        try:
            if method == "initialize":
                result = self.on_initialize(msg.get("params") or {})
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                result = self.on_call(msg.get("params") or {})
            else:
                self.send({"jsonrpc": "2.0", "id": mid,
                           "error": {"code": -32601, "message": "Method not found: %s" % method}})
                return
            self.send({"jsonrpc": "2.0", "id": mid, "result": result})
        except Exception as e:
            log("处理 %s 出错：%s" % (method, traceback.format_exc()))
            self.send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": "Internal error: %s" % e}})

    def on_initialize(self, params):
        self.client_caps = params.get("capabilities") or {}
        info = params.get("clientInfo") or {}
        self.client_name = ("%s %s" % (info.get("name", ""), info.get("version", ""))).strip()
        wanted = params.get("protocolVersion")
        version = wanted if wanted in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
        log("客户端 %s，协议版本 %s（请求 %s）" % (self.client_name or "未知", version, wanted))
        return {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO, "instructions": INSTRUCTIONS}

    def setup_workspace(self):
        root, source = None, None
        for name in ROOT_ENV_VARS:
            value = os.environ.get(name, "").strip()
            if value:
                root, source = value, "环境变量 %s" % name
                break
        if not root and "roots" in self.client_caps:
            roots = self.request_roots()
            if roots:
                root, source = roots[0], "客户端提供的 roots"
                if len(roots) > 1:
                    source += "（共 %d 个，只用第一个）" % len(roots)
        if not root:
            root, source = os.getcwd(), "启动时的当前目录"
        try:
            self.ws = core.Workspace(root, source, client_name=self.client_name)
            log("白名单：%s（%s）" % (self.ws.root, source))
        except core.ToolError as e:
            self.ws_error = "%s（白名单来源：%s，路径：%s）" % (e, source, root)
            log("白名单无效：%s" % self.ws_error)

    def request_roots(self):
        """向客户端要 roots，最多等 ROOTS_TIMEOUT_S 秒；期间收到的其他消息先存着，之后照常处理。"""
        self.request_seq += 1
        rid = "safe-edit-roots-%d" % self.request_seq
        self.send({"jsonrpc": "2.0", "id": rid, "method": "roots/list"})
        deadline = time.time() + ROOTS_TIMEOUT_S
        while True:
            left = deadline - time.time()
            if left <= 0:
                log("等待 roots/list 超时，改用当前目录")
                return []
            try:
                msg = self.inbox.get(timeout=left)
            except queue.Empty:
                log("等待 roots/list 超时，改用当前目录")
                return []
            if msg is None:
                self.backlog.append(None)
                return []
            if isinstance(msg, dict) and msg.get("id") == rid and "method" not in msg:
                if "error" in msg:
                    log("roots/list 出错：%s" % msg.get("error"))
                    return []
                roots = (msg.get("result") or {}).get("roots") or []
                return [p for p in (uri_to_path(r.get("uri")) for r in roots if isinstance(r, dict)) if p]
            self.backlog.append(msg)

    def on_call(self, params):
        name = params.get("name")
        args = params.get("arguments") or {}
        if name not in TOOL_NAMES:
            return text_result("没有这个工具：%s" % name, error=True)
        if self.ws is None and self.ws_error is None:
            self.setup_workspace()
        if self.ws is None:
            return text_result("safe_edit 不可用，白名单文件夹无效：%s" % self.ws_error, error=True)
        try:
            return text_result(self.ws.tool(name, args))
        except core.ToolError as e:
            return text_result("错误：%s" % e, error=True)
        except Exception as e:
            log(traceback.format_exc())
            return text_result("内部错误：%s: %s" % (type(e).__name__, e), error=True)


def main():
    try:
        Server().run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
