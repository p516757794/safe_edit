# -*- coding: utf-8 -*-
"""safe_edit 核心逻辑，MCP 服务（safe_edit_server.py）和命令行（safe_edit_cli.py）共用。

先检测加密状态；MCP/CLI 只处理加密文件，明文文件交给普通工具：
- 修改接口默认准备后直接写回；dry_run=True 才只预览，不再要求逐次确认 diff；
- 只用受信任的 Python 读取明文；
- 自动识别并保留每个文件原来的编码（ASCII / GBK / UTF-8 / UTF-8 BOM）和行尾；
- 文档类文件（utf8_exts，默认 .md / .txt / .json）新建用 UTF-8，出现 GBK 存不了的字符时整份改存 UTF-8；
- 每组旧内容必须在文件里恰好出现一次，改动范围以外的字节保证不变；
- 写回用 'r+b' 原地整文件覆盖：已加密的文件写完仍然加密（2026-10-19 在 E:\\soft 实测）；
- 写回前用 PowerShell 按原样复制密文做备份，写回后核对内容和磁盘上的加密状态；
- 写回环节任何一步出错都会写锁文件，拒绝之后的修改，直到有人检查后删除锁文件。

只用 Python 标准库。
"""

import codecs
import datetime
import difflib
import fnmatch
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import uuid
from collections import OrderedDict

VERSION = "1.5.0"
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(TOOL_DIR, "config.json")

DEFAULT_CONFIG = {
    "backup_root": r"E:\soft\_safe_edit_backups",
    "whitelist_root": "",
    "exclude_dirs": [r"E:\soft\_safe_edit_backups", r"E:\soft\_codex_backups"],
    "forbidden_roots": [],
    "deny_read": [],
    "skip_dir_names": ["Objects", "Listings", "OBJ", "Output", "DebugConfig", ".git", ".svn"],
    "search_skip_lib_dirs": ["Lib", "Library", "Libraries", "CMSIS", "Drivers", "Device", "Startup", ".cmsis"],
    "protected_exts": [".uvprojx", ".uvoptx", ".uvguix", ".uvproj", ".uvopt"],
    "search_exts": [".c", ".h"],
    "max_file_bytes": 2000000,
    "max_read_lines": 300,
    "default_read_lines": 40,
    "search_max_results": 20,
    "search_max_files": 5000,
    "search_time_limit_s": 20,
    "diff_context_lines": 1,
    "diff_to_file": True,
    "diff_viewer": "",
    "new_file_encoding": "gbk",
    "utf8_exts": [".md", ".txt", ".json"],
    "new_file_eol": "CRLF",
    "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
}

ENCODING_LABELS = {"ascii": "ASCII（纯英文）", "gbk": "GBK", "utf-8": "UTF-8"}
MAX_EDITS = 20
MAX_CHECK_FILES = 50
MAX_PENDING = 30
CACHE_LIMIT_CHARS = 64 * 1024 * 1024
INLINE_DIFF_MAX_LINES = 400
_EOL_RE = re.compile(r"\r\n|\n|\r")
_WS_RE = re.compile(r"\s+")

# PowerShell 不受加密软件管控，读到的是磁盘上的原始字节（加密文件就是密文）。
_PS_STATE = (
    "$ErrorActionPreference = 'Stop'; "
    "$b = [System.IO.File]::ReadAllBytes($env:SE_SRC); "
    "$h = [System.Security.Cryptography.SHA256]::Create().ComputeHash($b); "
    "[Console]::Out.Write($b.Length.ToString() + ' ' + [BitConverter]::ToString($h).Replace('-', ''))"
)
_PS_BACKUP = (
    "$ErrorActionPreference = 'Stop'; "
    "$sha = [System.Security.Cryptography.SHA256]::Create(); "
    "$b = [System.IO.File]::ReadAllBytes($env:SE_SRC); "
    "$h1 = [BitConverter]::ToString($sha.ComputeHash($b)).Replace('-', ''); "
    "[System.IO.File]::Copy($env:SE_SRC, $env:SE_DST, $false); "
    "$c = [System.IO.File]::ReadAllBytes($env:SE_DST); "
    "$h2 = [BitConverter]::ToString($sha.ComputeHash($c)).Replace('-', ''); "
    "[Console]::Out.Write($b.Length.ToString() + ' ' + $h1 + ' ' + $h2)"
)


class ToolError(Exception):
    """可以预期的错误：原样告诉调用方，文件没有被改动。"""


class WriteFailure(ToolError):
    """写回环节的错误：工具会被锁住。"""


# ---------------------------------------------------------------- 配置


def load_config(path=None):
    """读取配置：优先用环境变量 SAFE_EDIT_CONFIG 指定的文件，否则用工具目录下的 config.json。"""
    path = path or os.environ.get("SAFE_EDIT_CONFIG") or DEFAULT_CONFIG_PATH
    cfg = dict(DEFAULT_CONFIG)
    cfg["_path"] = None
    if os.path.isfile(path):
        try:
            with open(path, "rb") as f:
                user = json.loads(f.read().decode("utf-8-sig"))
        except (OSError, UnicodeDecodeError, ValueError) as e:
            raise ToolError("配置文件读不了或格式不对：%s（%s）" % (path, e))
        if not isinstance(user, dict):
            raise ToolError("配置文件顶层必须是 JSON 对象：%s" % path)
        for key, value in user.items():
            if key.startswith("_"):
                continue
            if key not in DEFAULT_CONFIG:
                raise ToolError("配置文件里有不认识的项“%s”：%s" % (key, path))
            cfg[key] = value
        cfg["_path"] = path
    return cfg


# ---------------------------------------------------------------- 小工具


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def _norm(path):
    return os.path.normcase(os.path.normpath(path))


def is_inside(child, parent):
    """child 是否就是 parent 或在 parent 里面（不区分大小写）。"""
    c, p = _norm(child), _norm(parent)
    if c == p:
        return True
    if not p.endswith(os.sep):
        p += os.sep
    return c.startswith(p)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _line_of_offset(data, offset):
    return data.count(b"\n", 0, offset) + 1


def _no_window():
    return {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


# ---------------------------------------------------------------- 编码


def decode_source(data):
    """识别编码并解码，返回 (text, encoding, bom)。encoding 是 'ascii'、'utf-8' 或 'gbk'。"""
    if data.startswith(codecs.BOM_UTF8):
        body = data[len(codecs.BOM_UTF8):]
        try:
            return body.decode("utf-8"), "utf-8", True
        except UnicodeDecodeError as e:
            raise ToolError("文件带 UTF-8 BOM，但第 %d 行不是合法的 UTF-8" % _line_of_offset(body, e.start))
    if data.startswith(codecs.BOM_UTF16_LE) or data.startswith(codecs.BOM_UTF16_BE):
        raise ToolError("不支持 UTF-16 编码的文件")
    if b"\x00" in data:
        raise ToolError("文件里有 0 字节，像是二进制文件，不处理")
    for enc in ("ascii", "utf-8"):
        try:
            return data.decode(enc), enc, False
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("gbk"), "gbk", False
    except UnicodeDecodeError as e:
        raise ToolError("既不是合法的 UTF-8 也不是合法的 GBK，第 %d 行有无法识别的字节，请先在 Keil 里检查这一行"
                        % _line_of_offset(data, e.start))


def encode_body(text, encoding, fallback="gbk", upgrade=False):
    """把文本按编码变回字节（不含 BOM），返回 (bytes, 实际编码)。纯英文文件出现非 ASCII 字符时改用 fallback；
    upgrade 为真（文档类文件）时，出现 GBK 表示不了的字符就整份改用 UTF-8。"""
    try:
        if encoding == "ascii":
            try:
                return text.encode("ascii"), "ascii"
            except UnicodeEncodeError:
                return text.encode(fallback), fallback
        return text.encode(encoding), encoding
    except UnicodeEncodeError as e:
        if upgrade:
            return text.encode("utf-8"), "utf-8"
        ch = e.object[e.start]
        raise ToolError("字符“%s”（U+%04X）无法用 %s 表示，请换成能表示的字符" % (ch, ord(ch), e.encoding.upper()))


def encoding_label(encoding, bom=False):
    label = ENCODING_LABELS.get(encoding, encoding)
    return label + "（带 BOM）" if bom else label


def check_roundtrip(data, text, encoding, bom):
    body, _ = encode_body(text, encoding)
    if ((codecs.BOM_UTF8 + body) if bom else body) != data:
        raise ToolError("文件解码后再编码和原文件不完全一致（%s），为避免改坏，不处理" % encoding_label(encoding, bom))


# ---------------------------------------------------------------- 行尾与行号


def split_lines(text):
    """按 CRLF / LF / CR 分行，行号和编辑器一致。"""
    if not text:
        return []
    lines = _EOL_RE.split(text)
    if lines[-1] == "":
        lines.pop()
    return lines


def line_no(text, idx):
    """text 第 idx 个字符所在的行号（从 1 开始）。"""
    return len(_EOL_RE.findall(text, 0, idx)) + 1


def eol_counts(text):
    crlf = text.count("\r\n")
    return crlf, text.count("\n") - crlf, text.count("\r") - crlf


def eol_name(text):
    crlf, lf, cr = eol_counts(text)
    kinds = [(n, c) for n, c in (("CRLF", crlf), ("LF", lf), ("CR", cr)) if c]
    if not kinds:
        return "无换行"
    if len(kinds) == 1:
        return kinds[0][0]
    return "混合（" + "，".join("%s %d 处" % k for k in kinds) + "）"


def dominant_eol(text, default="\r\n"):
    crlf, lf, _ = eol_counts(text)
    if crlf == 0 and lf == 0:
        return default
    return "\r\n" if crlf >= lf else "\n"


def normalize_with_map(text):
    """把 CRLF 换成 LF，返回 (normalized, n2t)：n2t[i] 是 normalized 第 i 个字符在原文里的位置，末尾多一项 len(text)。"""
    parts = []
    n2t = []
    pos = 0
    for m in re.finditer("\r\n", text):
        start = m.start()
        parts.append(text[pos:start])
        n2t.extend(range(pos, start))
        parts.append("\n")
        n2t.append(start)
        pos = m.end()
    parts.append(text[pos:])
    n2t.extend(range(pos, len(text)))
    n2t.append(len(text))
    return "".join(parts), n2t


def _eol_for_span(text, start, end, default):
    """新写入的换行用什么：沿用被替换那段的换行；那段没有换行时看后面最近的换行；再不行用文件里最多的那种。"""
    crlf, lf, _ = eol_counts(text[start:end])
    if crlf or lf:
        return "\r\n" if crlf >= lf else "\n"
    m = _EOL_RE.search(text, end)
    if m and m.group() in ("\r\n", "\n"):
        return m.group()
    return dominant_eol(text, default)


def _span_lines(text, start, end):
    """被替换的那段在原文里占第几行到第几行。"""
    first = line_no(text, start)
    span = text[start:end]
    if span.endswith("\r\n"):
        span = span[:-2]
    elif span.endswith(("\n", "\r")):
        span = span[:-1]
    return first, first + len(_EOL_RE.findall(span))


def _line_table(text):
    """每一行的 (行首, 内容结尾, 连换行的结尾) 位置；下标 0 是第 1 行，分行方式和 split_lines 一致。"""
    table, pos = [], 0
    for m in _EOL_RE.finditer(text):
        table.append((pos, m.start(), m.end()))
        pos = m.end()
    if pos < len(text):
        table.append((pos, len(text), len(text)))
    return table


def _norm_ws(s):
    return " ".join(s.split())


def _clip(s, n=80):
    s = s.strip()
    return s if len(s) <= n else s[:n] + "……"


def _check_anchor(what, text, table, n, anchor, key):
    """按行号修改时核对这一行的内容：不计较空白；长行可以只写开头（至少 10 个字符）。"""
    if not isinstance(anchor, str):
        raise ToolError("%s：按行号修改时要给出 %s（第 %d 行的内容），用来核对行号" % (what, key, n))
    actual = text[table[n - 1][0]:table[n - 1][1]]
    want, got = _norm_ws(anchor), _norm_ws(actual)
    if want == got or (len(want) >= 10 and got.startswith(want)):
        return
    raise ToolError("%s：第 %d 行实际是“%s”，和 %s 对不上，请用 read_source 确认行号" % (what, n, _clip(actual), key))


def _line_eol(text, table, n, default_eol):
    """第 n 行自己的换行；没有换行或是单独的 CR 时，按 _eol_for_span 的规则取。"""
    content_end, line_end = table[n - 1][1], table[n - 1][2]
    eol = text[content_end:line_end]
    if eol in ("\r\n", "\n"):
        return eol
    return _eol_for_span(text, content_end, content_end, default_eol)


def _line_span(what, text, table, ed, default_eol):
    """按行号修改的一组，返回 (原文起点, 原文终点, 换好行尾的新内容)。行号都按修改前的原文件算。
    {start_line, end_line, new}：把这几行整行换成 new；new 为空字符串时删除这几行。
    {insert_after, new}：在第 insert_after 行后面插入 new，0 表示插在文件开头。
    new 末尾有没有换行都可以，工具按整行处理。"""
    if "insert_after" in ed and "start_line" in ed:
        raise ToolError("%s：start_line 和 insert_after 不能同时用" % what)
    new = ed.get("new")
    if not isinstance(new, str):
        raise ToolError("%s：new 必须是字符串" % what)
    total = len(table)
    body = new.replace("\r\n", "\n")
    if body.endswith("\n"):
        body = body[:-1]
    if "insert_after" in ed:
        n = _int(ed.get("insert_after"), None)
        if n is None or n < 0 or n > total:
            raise ToolError("%s：insert_after 应该在 0 到 %d 之间（0 表示插在文件开头）" % (what, total))
        if new == "":
            raise ToolError("%s：插入的内容不能为空" % what)
        if n == 0:
            eol = _eol_for_span(text, 0, 0, default_eol)
            return 0, 0, body.replace("\n", eol) + eol
        _check_anchor(what, text, table, n, ed.get("after_line"), "after_line")
        eol = _line_eol(text, table, n, default_eol)
        content_end, line_end = table[n - 1][1], table[n - 1][2]
        if line_end > content_end:
            return line_end, line_end, body.replace("\n", eol) + eol
        # 第 n 行是最后一行而且没有换行：先补一个换行再插入，文件末尾仍然没有换行
        return line_end, line_end, eol + body.replace("\n", eol)
    a = _int(ed.get("start_line"), None)
    b = _int(ed.get("end_line"), a)
    if a is None or b is None or a < 1 or b < a or b > total:
        raise ToolError("%s：行号范围不对（文件共 %d 行；start_line 从 1 开始，end_line 不能小于 start_line）"
                        % (what, total))
    _check_anchor(what, text, table, a, ed.get("first_line"), "first_line")
    if b > a:
        _check_anchor(what, text, table, b, ed.get("last_line"), "last_line")
    start = table[a - 1][0]
    content_end, end = table[b - 1][1], table[b - 1][2]
    has_eol = end > content_end
    if new == "":
        # 删除这几行（连同换行）；删的是没有换行的最后一行时，连上一行的换行一起删，文件末尾仍然没有换行
        if not has_eol and a > 1:
            start = table[a - 2][1]
        return start, end, ""
    eol = _line_eol(text, table, b, default_eol)
    new_t = body.replace("\n", eol)
    return start, end, (new_t + eol) if has_eol else new_t


# ---------------------------------------------------------------- 修改


def _is_line_edit(ed):
    return isinstance(ed, dict) and ("start_line" in ed or "insert_after" in ed)


def apply_edits(text, edits, default_eol):
    """按"旧内容 → 新内容"或按行号修改文本。返回 (new_text, spans, ranges)。
    spans 是 [(原文起点, 原文终点, 换好行尾的新内容, 组号)]，按位置排序；ranges 是每组对应的原文行号范围。"""
    norm, n2t = normalize_with_map(text)
    table = None
    spans = []
    for i, ed in enumerate(edits, 1):
        what = "第 %d 组修改" % i
        if not isinstance(ed, dict):
            raise ToolError("%s：格式不对，应该是 {\"old\": ..., \"new\": ...}，"
                            "或按行号的 {\"start_line\": ..., \"end_line\": ..., \"new\": ...}" % what)
        if _is_line_edit(ed):
            if "old" in ed:
                raise ToolError("%s：old 和行号不能同时用，请选一种" % what)
            if table is None:
                table = _line_table(text)
            start, end, new_t = _line_span(what, text, table, ed, default_eol)
            spans.append((start, end, new_t, i))
            continue
        old, new = ed.get("old"), ed.get("new")
        if not isinstance(old, str) or not isinstance(new, str):
            raise ToolError("%s：old 和 new 都必须是字符串" % what)
        old_n = old.replace("\r\n", "\n")
        if old_n == "":
            raise ToolError("%s：旧内容不能为空" % what)
        first = norm.find(old_n)
        if first < 0:
            raise ToolError("%s：没有找到旧内容。请先用 read_source 确认原文（注意空格、制表符和中文标点）" % what)
        second = norm.find(old_n, first + 1)
        if second >= 0:
            raise ToolError("%s：旧内容出现了不止一次（第 %d 行和第 %d 行），请多带几行上下文让它唯一"
                            % (what, line_no(norm, first), line_no(norm, second)))
        start, end = n2t[first], n2t[first + len(old_n)]
        eol = _eol_for_span(text, start, end, default_eol)
        spans.append((start, end, new.replace("\r\n", "\n").replace("\n", eol), i))
    spans.sort()
    for a, b in zip(spans, spans[1:]):
        if a[1] > b[0] or a[0] == a[1] == b[0] == b[1]:
            raise ToolError("第 %d 组和第 %d 组修改的范围重叠，请合并成一组" % (a[3], b[3]))
    out, ranges, pos = [], [], 0
    for start, end, new_t, _ in spans:
        out.append(text[pos:start])
        out.append(new_t)
        ranges.append(_span_lines(text, start, end))
        pos = end
    out.append(text[pos:])
    return "".join(out), spans, ranges


def verify_minimal(old_text, old_body, old_enc, spans, new_body, new_enc):
    """确认新内容 = 原文件没改动部分的原始字节 + 各处新内容，即改动范围以外一个字节都没变。"""
    def byte_pos(i):
        return len(old_text[:i].encode(old_enc))

    expected, pos = [], 0
    for start, end, new_t, _ in spans:
        expected.append(old_body[byte_pos(pos):byte_pos(start)])
        expected.append(new_t.encode(new_enc))
        pos = end
    expected.append(old_body[byte_pos(pos):])
    if b"".join(expected) != new_body:
        raise ToolError("内部校验失败：改动范围以外的字节和原文件不一致，已停止")


def verify_converted(old_text, spans, new_text, new_body, new_enc):
    """整份文件换了编码（文档类 GBK → UTF-8）时字节必然全变，改为按文字核对：
    改动范围以外的文字和原文件一致，新字节按新编码解出来正好是修改后的内容。"""
    expected, pos = [], 0
    for start, end, new_t, _ in spans:
        expected.append(old_text[pos:start])
        expected.append(new_t)
        pos = end
    expected.append(old_text[pos:])
    if "".join(expected) != new_text or new_body.decode(new_enc) != new_text:
        raise ToolError("内部校验失败：换编码后的内容和改动不一致，已停止")


def make_diff(old_text, new_text, rel, max_lines=INLINE_DIFF_MAX_LINES, context=3):
    """unified diff。max_lines 为 None 时不截断（写进 diff 文件给人看时用）。"""
    lines = list(difflib.unified_diff(split_lines(old_text), split_lines(new_text),
                                      "原文件/" + rel, "修改后/" + rel, n=context, lineterm=""))
    if max_lines and len(lines) > max_lines:
        lines = lines[:max_lines] + ["……（diff 太长，只显示前 %d 行）" % max_lines]
    return "\n".join(lines)


def _cap_lines(text, max_lines):
    lines = text.split("\n")
    if len(lines) <= max_lines:
        return text
    return "\n".join(lines[:max_lines] + ["……（太长，只显示前 %d 行）" % max_lines])


def _diff_counts(diff):
    """diff 里新增、删除了多少行（开头两行文件头不算）。"""
    add = rem = 0
    for i, line in enumerate(diff.split("\n")):
        if i < 2 and line.startswith(("--- ", "+++ ")):
            continue
        if line.startswith("+"):
            add += 1
        elif line.startswith("-"):
            rem += 1
    return add, rem


def _ranges_text(ranges):
    return "；".join(("第 %d 行" % a) if a == b else ("第 %d–%d 行" % (a, b)) for a, b in ranges)


# ---------------------------------------------------------------- 写盘


def write_in_place(path, data):
    """原地整文件覆盖：打开原文件从头写入，再截掉多余部分。已加密的文件写完仍然加密（2026-10-19 实测）。
    不能改成 open(path, 'wb') 或 PowerShell WriteAllBytes：那样会把加密文件变成明文。"""
    with open(path, "r+b") as f:
        f.seek(0)
        f.write(data)
        f.truncate()
        f.flush()
        os.fsync(f.fileno())


def create_new(path, data):
    """新建文件（文件已存在就报错）。受信任 Python 新建的文件是明文。"""
    with open(path, "xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


# ---------------------------------------------------------------- 参数


def _req_str(args, key):
    value = args.get(key)
    if not isinstance(value, str) or value == "":
        raise ToolError("缺少参数 %s（字符串）" % key)
    return value


def _opt_str(args, key):
    value = args.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ToolError("参数 %s 应该是字符串" % key)
    return value


def _int(value, default):
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ToolError("参数应该是整数：%r" % (value,))
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ToolError("参数应该是整数：%r" % (value,))


def _bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "y", "是")
    return bool(value)


def _str_list(value):
    if value is None or value == "" or value == []:
        return None
    if isinstance(value, str):
        return [s.strip() for s in value.split(",") if s.strip()]
    if isinstance(value, list) and all(isinstance(s, str) for s in value):
        return value
    raise ToolError("exts 应该是字符串列表，比如 [\".c\", \".h\"]")


def _edits_arg(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            raise ToolError("edits 应该是列表，比如 [{\"old\": \"...\", \"new\": \"...\"}]，"
                            "或按行号的 [{\"start_line\": 10, \"end_line\": 12, \"first_line\": \"...\", "
                            "\"last_line\": \"...\", \"new\": \"...\"}]")
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list) or not value:
        raise ToolError("edits 必须是至少一组修改的列表")
    if len(value) > MAX_EDITS:
        raise ToolError("一次最多 %d 组修改，请分几次做" % MAX_EDITS)
    return value


# ---------------------------------------------------------------- 工作区


class Workspace:
    """一个白名单文件夹。所有读写都经过这里的检查。"""

    def __init__(self, root, root_source, cfg=None, client_name=""):
        self.cfg = cfg if cfg is not None else load_config()
        self.client_name = client_name
        self.started = _now()
        self.session_id = uuid.uuid4().hex[:8]
        self.pending = OrderedDict()
        self.last_edit_id = None
        self._mem_lock = None
        self._cache = OrderedDict()
        self._cache_chars = 0
        # diff 给项目负责人看的方式："file" 写成文件（默认），"inline" 直接放在返回结果里
        self.review = "file" if _bool(self.cfg.get("diff_to_file")) else "inline"
        self.open_viewer = True
        self.excluded = [os.path.realpath(TOOL_DIR)]
        for d in [self.cfg["backup_root"]] + list(self.cfg.get("exclude_dirs") or []):
            if d and all(_norm(os.path.realpath(d)) != _norm(x) for x in self.excluded):
                self.excluded.append(os.path.realpath(d))
        fixed = str(self.cfg.get("whitelist_root") or "").strip()
        if fixed:
            # 白名单固定为配置的文件夹（比如整个 E 盘）；会话所在的文件夹只作为工作文件夹
            self.root = self._check_fixed_root(fixed)
            self.root_source = "配置文件 whitelist_root"
            self.base, self.base_source = self._pick_base(root, root_source)
        else:
            self.root = self._check_root(root)
            self.root_source = root_source
            self.base, self.base_source = self.root, root_source

    # ---- 白名单与路径

    def _check_root(self, root):
        if not root or not str(root).strip():
            raise ToolError("没有确定白名单文件夹")
        real = os.path.realpath(str(root).strip())
        if not os.path.isdir(real):
            raise ToolError("白名单文件夹不存在：%s" % real)
        if real.startswith("\\\\"):
            raise ToolError("白名单不能是网络路径：%s" % real)
        if os.path.splitdrive(real)[1] in ("", "\\", "/"):
            raise ToolError("白名单不能是磁盘根目录：%s" % real)
        if is_inside(os.path.realpath(os.path.expanduser("~")), real):
            raise ToolError("白名单不能是用户目录或它的上级：%s" % real)
        for f in self.cfg.get("forbidden_roots") or []:
            if f and _norm(os.path.realpath(f)) == _norm(real):
                raise ToolError("白名单文件夹在配置的禁止清单里：%s" % real)
        for ex in self.excluded:
            if is_inside(real, ex):
                raise ToolError("白名单文件夹在排除目录里（工具自己的文件夹或备份目录）：%s" % real)
        return real

    def _check_fixed_root(self, path):
        real = os.path.realpath(path)
        if not os.path.isdir(real):
            raise ToolError("配置的白名单 whitelist_root 不存在：%s" % real)
        if real.startswith("\\\\"):
            raise ToolError("白名单不能是网络路径：%s" % real)
        if is_inside(os.path.realpath(os.path.expanduser("~")), real):
            raise ToolError("白名单不能包含用户目录（比如用户目录所在的盘）：%s" % real)
        for ex in self.excluded:
            if is_inside(real, ex):
                raise ToolError("白名单在排除目录里：%s" % real)
        return real

    def _pick_base(self, root, source):
        """工作文件夹：会话所在的文件夹在白名单里就用它，否则用白名单根目录。相对路径和搜索都从这里开始。"""
        if root and str(root).strip():
            real = os.path.realpath(str(root).strip())
            if os.path.isdir(real) and is_inside(real, self.root) and not self._is_excluded(real):
                return real, source
            return self.root, "白名单根目录（%s 提供的 %s 不在白名单里，没有采用）" % (source, real)
        return self.root, "白名单根目录"

    def _display(self, real):
        """给人看的路径：在工作文件夹里用相对路径，否则用完整路径。"""
        if _norm(real) != _norm(self.base) and is_inside(real, self.base):
            return os.path.relpath(real, self.base)
        return real

    def _check_path_text(self, path):
        if not isinstance(path, str) or not path.strip():
            raise ToolError("路径不能为空")
        p = path.strip().strip('"').strip("'")
        if p.startswith("\\\\") or p.startswith("//"):
            raise ToolError("不支持网络路径或设备路径：%s" % p)
        if ":" in os.path.splitdrive(p)[1]:
            raise ToolError("路径里不能有冒号（数据流路径）：%s" % p)
        real = os.path.realpath(p if os.path.isabs(p) else os.path.join(self.base, p))
        if real.startswith("\\\\"):
            raise ToolError("不支持这个路径：%s" % p)
        if not is_inside(real, self.root):
            raise ToolError("不在白名单文件夹里：%s（白名单：%s）" % (real, self.root))
        for ex in self.excluded:
            if is_inside(real, ex):
                raise ToolError("在排除目录里，不允许访问：%s" % real)
        return real

    def _denied(self, real):
        rel = os.path.normcase(os.path.relpath(real, self.root))
        full = os.path.normcase(real)
        for pat in self.cfg.get("deny_read") or []:
            if not pat:
                continue
            pp = os.path.normcase(os.path.normpath(str(pat)))
            target = full if os.path.isabs(pp) else rel
            if fnmatch.fnmatch(target, pp) or fnmatch.fnmatch(target, pp.rstrip("\\/") + os.sep + "*"):
                return True
        return False

    def resolve(self, path, must_exist=True):
        """检查并解析文件路径，返回 (完整路径, 相对白名单的路径)。"""
        real = self._check_path_text(path)
        if _norm(real) == _norm(self.root):
            raise ToolError("这是白名单文件夹本身，不是文件：%s" % real)
        if self._denied(real):
            raise ToolError("在“AI 不许读”清单里：%s" % self._display(real))
        if must_exist and not os.path.isfile(real):
            raise ToolError("文件不存在：%s" % real)
        return real, self._display(real)

    def resolve_dir(self, folder):
        if not folder or folder.strip() in (".", ""):
            return self.base
        real = self._check_path_text(folder)
        if not os.path.isdir(real):
            raise ToolError("文件夹不存在：%s" % real)
        return real

    def _is_excluded(self, real):
        return any(is_inside(real, ex) for ex in self.excluded)

    def _check_editable(self, real):
        if os.path.splitext(real)[1].lower() in [e.lower() for e in self.cfg.get("protected_exts") or []]:
            raise ToolError("Keil 工程文件不允许修改：%s" % os.path.basename(real))

    # ---- 读取

    def _read(self, real):
        size = os.path.getsize(real)
        limit = int(self.cfg["max_file_bytes"])
        if size > limit:
            raise ToolError("文件太大（%d 字节），超过上限 %d 字节：%s" % (size, limit, real))
        with open(real, "rb") as f:
            data = f.read()
        if len(data) > limit:
            raise ToolError("文件太大（%d 字节），超过上限 %d 字节：%s" % (len(data), limit, real))
        return data

    def load(self, real):
        """读取并解码，返回 (data, text, encoding, bom)。解码再编码必须和原文件一致。"""
        data = self._read(real)
        text, enc, bom = decode_source(data)
        check_roundtrip(data, text, enc, bom)
        return data, text, enc, bom

    def check_file(self, path):
        """只检查元数据，不返回源码；用两种读取视角比对加密状态。"""
        real, rel = self.resolve(path, must_exist=False)
        try:
            before = os.stat(real)
        except FileNotFoundError:
            return {"real": real, "rel": rel, "exists": False,
                    "encrypted": None, "use_safe_edit": False, "encoding": "", "sha256": ""}
        except OSError as e:
            raise ToolError("无法确定加密状态，已停止；不得当作明文继续：%s（%s）" % (real, e))
        if not stat.S_ISREG(before.st_mode):
            raise ToolError("目标不是文件：%s" % real)
        try:
            data = self._read(real)
            sha = sha256_hex(data)
            state = self._disk_state(real, sha)
            after_data = self._read(real)
            after = os.stat(real)
        except (OSError, WriteFailure) as e:
            raise ToolError("无法确定加密状态，已停止；不得当作明文继续：%s（%s）" % (real, e))
        signature = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if signature(before) != signature(after) or sha256_hex(after_data) != sha:
            raise ToolError("检测期间文件发生变化，无法确定加密状态，请重新检查：%s" % real)
        try:
            _, enc, bom = decode_source(data)
            encoding = encoding_label(enc, bom)
        except ToolError:
            encoding = "无法识别（仅完成加密检测）"
        return {"real": real, "rel": rel, "exists": True, "encrypted": state["encrypted"],
                "use_safe_edit": state["encrypted"], "encoding": encoding, "sha256": sha}

    def check_files(self, paths):
        """同一次调用检测多个目标；每个文件仍独立执行完整的权限和加密检查。"""
        if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_CHECK_FILES:
            raise ToolError("paths 必须是包含 1–%d 个路径的数组" % MAX_CHECK_FILES)
        if any(not isinstance(path, str) or not path.strip() for path in paths):
            raise ToolError("paths 中每个路径必须是非空字符串")
        # 全部成功后才返回结果；任一失败会终止，不把未知状态当作明文。
        return [self.check_file(path) for path in paths]

    def _cached_text(self, real):
        """搜索用：按修改时间和大小缓存解码后的文本；解不开的文件返回 None。"""
        st = os.stat(real)
        key = _norm(real)
        hit = self._cache.get(key)
        if hit and hit[0] == st.st_mtime_ns and hit[1] == st.st_size:
            self._cache.move_to_end(key)
            return hit[2]
        text = None
        if st.st_size <= int(self.cfg["max_file_bytes"]):
            try:
                with open(real, "rb") as f:
                    text = decode_source(f.read())[0]
            except (OSError, ToolError):
                text = None
        if hit:
            self._cache_chars -= len(hit[2] or "")
        self._cache[key] = (st.st_mtime_ns, st.st_size, text)
        self._cache.move_to_end(key)
        self._cache_chars += len(text or "")
        while self._cache_chars > CACHE_LIMIT_CHARS and len(self._cache) > 1:
            _, old = self._cache.popitem(last=False)
            self._cache_chars -= len(old[2] or "")
        return text

    def _lib_dirs_for(self, base):
        """搜索时要跳过的厂家库目录名（小写）。要搜的文件夹本身就在库目录里（比如 folder 指定了 Lib）时不跳过。"""
        libs = {s.lower() for s in self.cfg.get("search_skip_lib_dirs") or []}
        ref = self.base if is_inside(base, self.base) else self.root
        try:
            parts = os.path.relpath(base, ref).split(os.sep)
        except ValueError:
            parts = []
        if any(part.lower() in libs for part in parts):
            return set()
        return libs

    def search(self, pattern, regex=False, folder="", exts=None, ignore_case=False, max_results=None,
               files_only=False, encrypted_only=False):
        """hits 是 [(显示路径, 行号, 该行内容)]；files 是 [(显示路径, 命中数)]。
        files_only 为真时只统计每个文件的命中数，不收集内容，max_results 限制的是文件数。"""
        if not isinstance(pattern, str) or pattern == "":
            raise ToolError("搜索内容不能为空")
        try:
            rx = re.compile(pattern if regex else re.escape(pattern), re.IGNORECASE if ignore_case else 0)
        except re.error as e:
            raise ToolError("正则表达式有误：%s" % e)
        base = self.resolve_dir(folder)
        exts = [(e if e.startswith(".") else "." + e).lower() for e in (exts or self.cfg["search_exts"])]
        limit = max(1, min(_int(max_results, None) or int(self.cfg["search_max_results"]), 500))
        max_files = int(self.cfg["search_max_files"])
        skip = {s.lower() for s in self.cfg.get("skip_dir_names") or []}
        libs = self._lib_dirs_for(base)
        t0 = time.time()
        deadline = t0 + float(self.cfg["search_time_limit_s"])
        hits, files, unreadable, skipped_libs, scanned, stop = [], [], [], [], 0, ""
        skipped_plain = []
        for dirpath, dirnames, filenames in os.walk(base):
            keep = []
            for d in sorted(dirnames):
                low = d.lower()
                if low in skip or self._is_excluded(os.path.join(dirpath, d)):
                    continue
                if low in libs:
                    skipped_libs.append(self._display(os.path.join(dirpath, d)))
                    continue
                keep.append(d)
            dirnames[:] = keep
            for fn in sorted(filenames):
                if os.path.splitext(fn)[1].lower() not in exts:
                    continue
                real = os.path.join(dirpath, fn)
                if self._denied(real):
                    continue
                if scanned >= max_files:
                    stop = "扫描的文件数达到上限 %d 个" % max_files
                    break
                if time.time() > deadline:
                    stop = "用时超过上限 %s 秒" % self.cfg["search_time_limit_s"]
                    break
                scanned += 1
                # resolve 校验链接目标、白名单、排除目录和 deny_read 后才检查内容。
                real, rel = self.resolve(real)
                if encrypted_only and not self.check_file(real)["use_safe_edit"]:
                    skipped_plain.append(rel)
                    continue
                text = self._cached_text(real)
                if text is None:
                    unreadable.append(rel)
                    continue
                count = 0
                for n, line in enumerate(split_lines(text), 1):
                    if rx.search(line):
                        count += 1
                        if files_only:
                            continue
                        # 连续空白（比如注释前的对齐空格）压成一个空格；搜索结果只用来定位，精确内容用 read_source 读
                        hits.append((rel, n, _WS_RE.sub(" ", line.strip())[:200]))
                        if len(hits) >= limit:
                            stop = "结果达到上限 %d 条" % limit
                            break
                if count:
                    files.append((rel, count))
                    if files_only and len(files) >= limit:
                        stop = "结果达到上限 %d 个文件" % limit
                if stop:
                    break
            if stop:
                break
        return {"base": base, "hits": hits, "files": files, "files_only": bool(files_only), "scanned": scanned,
                "stop": stop, "unreadable": unreadable, "skipped_libs": skipped_libs,
                "skipped_plain": skipped_plain, "encrypted_only": encrypted_only, "seconds": time.time() - t0}

    def read_source(self, path, start_line=1, end_line=None):
        real, rel = self.resolve(path)
        data, text, enc, bom = self.load(real)
        lines = split_lines(text)
        total = len(lines)
        maxn = int(self.cfg["max_read_lines"])
        # 不写结束行时只读 default_read_lines 行（默认 40），写了也最多 max_read_lines 行
        dflt = max(1, min(int(self.cfg.get("default_read_lines") or maxn), maxn))
        start = max(1, _int(start_line, 1))
        want_end = _int(end_line, None)
        end = min(want_end if want_end else start + dflt - 1, start + maxn - 1, total)
        note = ""
        if start > total:
            note = "文件只有 %d 行" % total
        elif end < (want_end or 0) and end < total:
            note = "一次最多返回 %d 行，后面的请从第 %d 行继续读" % (maxn, end + 1)
        elif not want_end and end < total:
            note = "后面还有内容，请从第 %d 行继续读（共 %d 行）" % (end + 1, total)
        body = "\n".join("%6d\t%s" % (i, lines[i - 1]) for i in range(start, end + 1))
        return {"real": real, "rel": rel, "encoding": encoding_label(enc, bom), "eol": eol_name(text),
                "total": total, "sha256": sha256_hex(data), "start": start, "end": end, "note": note,
                "body": body}

    # ---- 准备修改

    def _add_pending(self, item):
        eid = uuid.uuid4().hex[:8]
        self.pending[eid] = item
        while len(self.pending) > MAX_PENDING:
            self.pending.popitem(last=False)
        self.last_edit_id = eid
        return eid

    def _default_eol(self):
        return "\r\n" if str(self.cfg["new_file_eol"]).upper() == "CRLF" else "\n"

    def _utf8_doc(self, real):
        """文档类文件（utf8_exts）：新建用 UTF-8，出现 GBK 存不了的字符时整份改存 UTF-8。"""
        return os.path.splitext(real)[1].lower() in [e.lower() for e in self.cfg.get("utf8_exts") or []]

    def prepare_edit(self, path, edits, base_sha256="", note=""):
        self._check_unlocked()
        real, rel = self.resolve(path)
        self._check_editable(real)
        edits = _edits_arg(edits)
        data, text, enc, bom = self.load(real)
        sha = sha256_hex(data)
        if base_sha256 and base_sha256.strip().lower() != sha:
            raise ToolError("文件在你读取之后变了（SHA-256 不一致），请重新 read_source 后再准备修改")
        if not base_sha256 and any(_is_line_edit(e) for e in edits):
            raise ToolError("按行号修改时必须提供 base_sha256（read_source 或上一次 commit_edit 返回的），"
                            "确保行号对应的是你读到的那一版文件")
        new_text, spans, ranges = apply_edits(text, edits, dominant_eol(text, self._default_eol()))
        doc = self._utf8_doc(real)
        new_body, new_enc = encode_body(new_text, enc, "utf-8" if doc else self.cfg["new_file_encoding"], upgrade=doc)
        old_body = data[len(codecs.BOM_UTF8):] if bom else data
        if new_enc != enc and enc != "ascii":
            verify_converted(text, spans, new_text, new_body, new_enc)
        else:
            verify_minimal(text, old_body, enc, spans, new_body, new_enc)
        new_data = (codecs.BOM_UTF8 + new_body) if bom else new_body
        if new_data == data:
            raise ToolError("改完和原文件完全一样，不需要写回")
        eid = self._add_pending({
            "kind": "edit", "mode": "edit", "real": real, "rel": rel, "base_sha": sha, "new_data": new_data,
            "enc_before": encoding_label(enc, bom), "enc_after": encoding_label(new_enc, bom),
            "ranges": ranges, "note": note or ""})
        return {"edit_id": eid, "real": real, "rel": rel, "enc_before": encoding_label(enc, bom),
                "enc_after": encoding_label(new_enc, bom), "ranges": ranges, "note": note or "",
                "diff": make_diff(text, new_text, rel, max_lines=None, context=self._diff_context())}

    def _diff_context(self):
        return max(0, _int(self.cfg.get("diff_context_lines"), 3))

    def prepare_new_file(self, path, content, note=""):
        self._check_unlocked()
        real, rel = self.resolve(path, must_exist=False)
        self._check_editable(real)
        if not isinstance(content, str):
            raise ToolError("content 必须是字符串")
        parent = os.path.dirname(real)
        if not os.path.isdir(parent):
            raise ToolError("上级文件夹不存在：%s，请先建好文件夹" % parent)
        eol = self._default_eol()
        text = content.replace("\r\n", "\n").replace("\n", eol)
        enc = "utf-8" if self._utf8_doc(real) else self.cfg["new_file_encoding"]
        data, enc = encode_body(text, enc, enc)
        if os.path.exists(real):
            if not os.path.isfile(real):
                raise ToolError("目标已存在，而且不是文件：%s" % real)
            old = self._read(real)
            if old:
                raise ToolError("文件已存在且有内容，请用 prepare_edit 修改：%s" % rel)
            mode, base = "fill_empty", sha256_hex(old)
        else:
            mode, base = "create", None
        lines = split_lines(text)
        eid = self._add_pending({
            "kind": "new", "mode": mode, "real": real, "rel": rel, "base_sha": base, "new_data": data,
            "enc_before": "", "enc_after": encoding_label(enc), "ranges": [(1, max(1, len(lines)))],
            "note": note or ""})
        preview = "\n".join("%6d\t%s" % (i, s) for i, s in enumerate(lines[:20], 1))
        return {"edit_id": eid, "real": real, "rel": rel, "mode": mode, "encoding": encoding_label(enc),
                "eol": "CRLF" if eol == "\r\n" else "LF", "lines": len(lines), "preview": preview,
                "note": note or "", "diff": make_diff("", text, rel, max_lines=None, context=0)}

    # ---- 给项目负责人看的 diff

    def _write_review(self, eid, rel, head, body):
        """把 diff 写成文件给项目负责人看，返回完整路径：备份目录\\diffs\\日期\\时间_修改编号_文件名.diff，
        UTF-8（带 BOM）、CRLF，记事本等程序都能直接打开。"""
        now = datetime.datetime.now()
        folder = os.path.join(self.cfg["backup_root"], "diffs", now.strftime("%Y%m%d"))
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, "%s_%s_%s.diff" % (now.strftime("%H%M%S"), eid, os.path.basename(rel)))
        with open(path, "w", encoding="utf-8-sig", newline="\r\n") as f:
            f.write("\n".join(head) + "\n\n" + body + "\n")
        return path

    def _open_viewer(self, path):
        """用 diff_viewer 配置的程序打开 diff 文件，返回 (是否打开了, 出错说明)。
        diff_viewer 为空时不打开；写成 start 时用系统默认程序打开。"""
        viewer = str(self.cfg.get("diff_viewer") or "").strip()
        if not viewer or not self.open_viewer:
            return False, ""
        try:
            if viewer.lower() == "start":
                os.startfile(path)
            else:
                # 标准输入输出都接到空设备，不能占用 MCP 服务的 stdout
                subprocess.Popen([viewer, path], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
        except (OSError, ValueError, AttributeError) as e:
            return False, "用 %s 打开 diff 文件失败（%s），请手动打开" % (viewer, e)
        return True, ""

    def _review(self, r, show_diff):
        """决定 diff 怎么给项目负责人看：默认写成文件并打开，不返回给 AI；show_diff 为真或 diff_to_file 关掉时，
        直接放在返回结果里。返回 {"file": diff 文件路径, "opened": 是否打开了, "inline": 是否放进结果, "note": 说明}。"""
        out = {"file": "", "opened": False, "inline": bool(show_diff) or self.review != "file", "note": ""}
        if self.review != "file":
            return out
        head = ["修改编号：%s" % r["edit_id"], "完整路径：%s" % r["real"]]
        if r.get("encoding"):
            head.append("编码：%s" % r["encoding"])
        elif r.get("enc_before") != r.get("enc_after"):
            head.append("编码：%s → %s" % (r["enc_before"], r["enc_after"]))
        if r.get("ranges"):
            head.append("修改范围：%s" % _ranges_text(r["ranges"]))
        if r.get("note"):
            head.append("说明：%s" % r["note"])
        try:
            out["file"] = self._write_review(r["edit_id"], r["rel"], head, r["diff"])
        except OSError as e:
            out["inline"] = True
            out["note"] = "diff 文件写不了（%s），改为直接显示" % e
            return out
        out["opened"], out["note"] = self._open_viewer(out["file"])
        return out

    # ---- 写回

    def commit(self, edit_id):
        self._check_unlocked()
        eid = str(edit_id or "").strip()
        pe = self.pending.pop(eid, None)
        if pe is None:
            raise ToolError("修改编号 %s 不存在或已经用过，请重新 prepare" % eid)
        real, t0 = pe["real"], time.time()
        overwrite = pe["mode"] in ("edit", "fill_empty")
        # 写之前的检查：失败说明情况有变，文件没动，不锁工具。
        if overwrite:
            if not os.path.isfile(real):
                raise ToolError("文件已经不存在：%s" % real)
            if not os.access(real, os.W_OK):
                raise ToolError("文件是只读的，不能写回：%s" % real)
            cur = self._read(real)
            if sha256_hex(cur) != pe["base_sha"]:
                raise ToolError("文件在准备修改之后被改过，已停止。请重新读取后再准备修改：%s" % pe["rel"])
        elif os.path.exists(real):
            raise ToolError("文件已经存在了，已停止：%s" % real)
        backup, before, after = None, None, None
        try:
            if overwrite:
                backup, before = self._backup(real, eid, cur)
                if pe.get("encrypted_only") and not before["encrypted"]:
                    raise WriteFailure("写回前目标已不是加密文件，停止写入")
                write_in_place(real, pe["new_data"])
            else:
                create_new(real, pe["new_data"])
            got = self._read(real)
            if sha256_hex(got) != sha256_hex(pe["new_data"]):
                raise WriteFailure("写回后读出的内容和预期不一致")
            after = self._disk_state(real, sha256_hex(got))
            if before is not None and before["encrypted"] != after["encrypted"]:
                raise WriteFailure("写回后加密状态变了：写之前%s，写之后%s"
                                   % (_enc_word(before["encrypted"]), _enc_word(after["encrypted"])))
        except Exception as e:
            reason = str(e) if isinstance(e, ToolError) else "%s: %s" % (type(e).__name__, e)
            self._set_lock("修改编号 %s（%s）写回失败：%s" % (eid, pe["rel"], reason))
            self._log(pe, eid, "failed", error=reason, backup=backup, before=before, after=after)
            raise WriteFailure("写回失败，工具已锁定：%s%s" % (reason, ("。原文件的备份在 %s" % backup) if backup else ""))
        self._cache.pop(_norm(real), None)
        warning = self._log(pe, eid, "ok", backup=backup, before=before, after=after, sha_after=sha256_hex(got))
        return {"real": real, "rel": pe["rel"], "mode": pe["mode"], "sha256": sha256_hex(got),
                "before": before, "after": after, "backup": backup, "seconds": time.time() - t0,
                "warning": warning, "edit_id": eid, "ranges": pe["ranges"],
                "enc_before": pe["enc_before"], "enc_after": pe["enc_after"]}

    def _powershell(self, script, env_extra, timeout=60):
        env = dict(os.environ)
        env.update(env_extra)
        try:
            r = subprocess.run([self.cfg["powershell"], "-NoProfile", "-NonInteractive", "-Command", script],
                               env=env, capture_output=True, timeout=timeout, **_no_window())
        except (OSError, subprocess.TimeoutExpired) as e:
            raise WriteFailure("调用 PowerShell 失败：%s" % e)
        if r.returncode != 0:
            raise WriteFailure("PowerShell 出错（返回码 %d）：%s"
                               % (r.returncode, r.stderr.decode("gbk", "replace").strip()[:500]))
        return r.stdout.decode("ascii", "replace").strip()

    def _disk_state(self, real, plain_sha):
        """用 PowerShell 读磁盘上的原始字节：和受信任 Python 读到的明文不同，就说明文件是加密的。"""
        out = self._powershell(_PS_STATE, {"SE_SRC": real})
        try:
            raw_len, raw_sha = out.split()
            return {"encrypted": raw_sha.lower() != plain_sha, "raw_len": int(raw_len)}
        except ValueError:
            raise WriteFailure("查看加密状态时 PowerShell 返回了看不懂的结果：%s" % out[:200])

    def _backup_path(self, real, eid):
        """备份放在 备份目录\\<白名单名>_<编号>\\<时间>_<修改编号>\\<相对白名单的路径>。"""
        name = os.path.basename(self.root.rstrip("\\/")) or (os.path.splitdrive(self.root)[0].rstrip(":") + "盘")
        tag = hashlib.sha256(_norm(self.root).encode("utf-8")).hexdigest()[:8]
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(self.cfg["backup_root"], "%s_%s" % (name, tag), "%s_%s" % (stamp, eid),
                            os.path.relpath(real, self.root))

    def _backup(self, real, eid, plain):
        """用 PowerShell 按原样复制（加密文件复制的是密文，备份仍然加密），再用受信任 Python 核对备份内容。"""
        dst = self._backup_path(real, eid)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        out = self._powershell(_PS_BACKUP, {"SE_SRC": real, "SE_DST": dst})
        try:
            raw_len, h_src, h_dst = out.split()
        except ValueError:
            raise WriteFailure("备份时 PowerShell 返回了看不懂的结果：%s" % out[:200])
        if h_src.lower() != h_dst.lower():
            raise WriteFailure("备份文件和原文件的原始字节不一致：%s" % dst)
        with open(dst, "rb") as f:
            if sha256_hex(f.read()) != sha256_hex(plain):
                raise WriteFailure("用受信任 Python 读备份，内容和原文件不一致：%s" % dst)
        return dst, {"encrypted": h_src.lower() != sha256_hex(plain), "raw_len": int(raw_len)}

    # ---- 锁定

    @property
    def lock_path(self):
        return os.path.join(self.cfg["backup_root"], "LOCKED.txt")

    def lock_reason(self):
        try:
            with open(self.lock_path, "rb") as f:
                return f.read().decode("utf-8", "replace").strip() or "（锁文件存在，但没写原因）"
        except FileNotFoundError:
            return self._mem_lock
        except OSError as e:
            return "（锁文件读不了：%s）" % e

    def _set_lock(self, reason):
        try:
            os.makedirs(self.cfg["backup_root"], exist_ok=True)
            with open(self.lock_path, "a", encoding="utf-8") as f:
                f.write("[%s] %s\n" % (_now(), reason))
        except OSError as e:
            self._mem_lock = "%s（锁文件写不进去：%s）" % (reason, e)

    def _check_unlocked(self):
        reason = self.lock_reason()
        if reason:
            raise ToolError("工具已锁定，不能再改文件。原因：%s\n请检查文件和备份，确认没问题后删除 %s 再继续。"
                            % (reason, self.lock_path))

    # ---- 审计日志

    @property
    def log_path(self):
        return os.path.join(self.cfg["backup_root"], "audit.jsonl")

    def _log(self, pe, eid, result, error="", backup=None, before=None, after=None, sha_after=None):
        """只记元数据，不记代码。返回写日志失败时的提示。"""
        entry = {
            "time": _now(), "root": self.root, "base": self.base, "session": self.session_id,
            "file": pe["rel"], "path": pe["real"], "mode": pe["mode"], "edit_id": eid,
            "result": result, "error": error, "client": self.client_name, "note": pe.get("note", ""),
            "ranges": pe.get("ranges"), "encoding_before": pe.get("enc_before"), "encoding_after": pe.get("enc_after"),
            "sha_before": pe.get("base_sha"), "sha_after": sha_after,
            "encrypted_before": before["encrypted"] if before else None,
            "encrypted_after": after["encrypted"] if after else None, "backup": backup,
        }
        try:
            os.makedirs(self.cfg["backup_root"], exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            return ""
        except OSError as e:
            return "审计日志写入失败：%s" % e

    def change_log(self, since=None):
        """默认只列本次会话的修改；给了 since 就列这个白名单里该时间之后的所有修改。"""
        since_iso = None
        if since:
            s = str(since).strip().replace("/", "-").replace(" ", "T")
            if len(s) == 10:
                s += "T00:00"
            if len(s) == 16:
                s += ":00"
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", s):
                raise ToolError("since 的格式应该像 2026-10-19 15:30")
            since_iso = s
        entries = []
        if os.path.isfile(self.log_path):
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(e, dict):
                        continue
                    if since_iso is None:
                        if e.get("session") == self.session_id:
                            entries.append(e)
                    elif _norm(e.get("root", "")) == _norm(self.root) and str(e.get("time", "")) >= since_iso:
                        entries.append(e)
        title = "本次会话" if since_iso is None else "%s 之后" % since_iso.replace("T", " ")
        return title, entries

    # ---- 状态

    def status(self):
        cfg_path = self.cfg.get("_path")
        return {
            "version": VERSION, "root": self.root, "root_source": self.root_source,
            "base": self.base, "base_source": self.base_source,
            "client": self.client_name or "（未知）", "locked": self.lock_reason(),
            "pending": [(k, v["rel"]) for k, v in self.pending.items()],
            "backup_root": self.cfg["backup_root"], "excluded": self.excluded,
            "deny_read": list(self.cfg.get("deny_read") or []),
            "config": cfg_path or "未找到配置文件，使用默认配置", "python": sys.executable,
        }

    # ---- 对外的工具入口（MCP 和命令行共用），返回给 AI 看的文字

    def tool(self, name, args):
        args = args or {}
        if not isinstance(args, dict):
            raise ToolError("参数必须是 JSON 对象")
        if name == "get_status":
            return _fmt_status(self.status())
        if name == "check_file":
            if ("path" in args) == ("paths" in args):
                raise ToolError("path 和 paths 必须且只能提供一个")
            if "paths" in args:
                return "\n".join(_fmt_check_file(r) for r in self.check_files(args["paths"]))
            return _fmt_check_file(self.check_file(_req_str(args, "path")))
        if name == "search_code":
            return _fmt_search(self, self.search(
                _req_str(args, "pattern"), regex=_bool(args.get("regex")), folder=_opt_str(args, "folder"),
                exts=_str_list(args.get("exts")), ignore_case=_bool(args.get("ignore_case")),
                max_results=args.get("max_results"), files_only=_bool(args.get("files_only")),
                encrypted_only=True), args.get("pattern"))
        if name in ("read_source", "prepare_edit", "prepare_new_file"):
            path = _req_str(args, "path")
            route = self.check_file(path)
            if not route["use_safe_edit"]:
                return _fmt_check_file(route)
            if name == "read_source":
                return _fmt_read(self.read_source(path, args.get("start_line"), args.get("end_line")))
            # 按行号仍必须由调用方提供它读到的版本；不可用本次检测的哈希代填。
            if name == "prepare_edit":
                base_sha = _opt_str(args, "base_sha256")
                edits = _edits_arg(args.get("edits"))
                if not base_sha and any(_is_line_edit(e) for e in edits):
                    raise ToolError("按行号修改时必须提供 base_sha256（read_source 或上一次写回返回的）")
                r = self.prepare_edit(path, edits, base_sha or route["sha256"], _opt_str(args, "note"))
                formatter = _fmt_prepare
            else:
                if not isinstance(args.get("content"), str):
                    raise ToolError("缺少参数 content（字符串）")
                r = self.prepare_new_file(path, args["content"], _opt_str(args, "note"))
                if r["mode"] != "fill_empty":
                    self.pending.pop(r["edit_id"], None)
                    raise ToolError("检测后加密空文件已不存在，停止新建；请重新 check_file")
                formatter = _fmt_new
            self.pending[r["edit_id"]]["encrypted_only"] = True
            dry_run = _bool(args.get("dry_run"))
            old_viewer = self.open_viewer
            if not dry_run:
                self.open_viewer = False
            try:
                review = self._review(r, _bool(args.get("show_diff")))
            finally:
                self.open_viewer = old_viewer
            if dry_run:
                return formatter(r, review) + "\n预览完成：没有写盘；可用 commit_edit 直接写回。"
            return _fmt_commit(self.commit(r["edit_id"]), prepared=r, review=review)
        if name == "commit_edit":
            return _fmt_commit(self.commit(_req_str(args, "edit_id")))
        if name == "change_log":
            return _fmt_log(*self.change_log(args.get("since")))
        raise ToolError("没有这个工具：%s" % name)


# ---------------------------------------------------------------- 输出格式


def _enc_word(flag):
    return {True: "已加密", False: "明文", None: "未知"}[flag]


def _fmt_check_file(r):
    state = _enc_word(r["encrypted"]) if r["exists"] else "文件不存在"
    parts = [r["real"], state]
    if r["encoding"]:
        parts.append("编码：%s" % r["encoding"])
    parts.append("use_safe_edit: %s" % ("true" if r["use_safe_edit"] else "false"))
    return " | ".join(parts)


def _fmt_status(st):
    lines = [
        "safe_edit %s" % st["version"],
        "处理规则：先 check_file；仅处理加密文件；默认直接写回（dry_run=true 才只预览）",
        "白名单（可读写范围）：%s" % st["root"],
        "白名单来源：%s" % st["root_source"],
        "工作文件夹（相对路径和搜索的起点）：%s" % st["base"],
        "工作文件夹来源：%s" % st["base_source"],
        "客户端：%s" % st["client"],
        "锁定：%s" % ("否" if not st["locked"] else "是。" + st["locked"]),
        "待写回的修改：%s" % ("无" if not st["pending"] else "；".join("%s（%s）" % p for p in st["pending"])),
        "备份目录：%s" % st["backup_root"],
        "排除目录：%s" % "；".join(st["excluded"]),
        "AI 不许读：%s" % ("无" if not st["deny_read"] else "；".join(st["deny_read"])),
        "配置文件：%s" % st["config"],
        "Python：%s" % st["python"],
    ]
    return "\n".join(lines)


def _fmt_search(ws, r, pattern):
    where = "工作文件夹" if _norm(r["base"]) == _norm(ws.base) else ws._display(r["base"])
    if r["files_only"]:
        head = "在 %s 里搜索“%s”（只列文件）：%d 个文件，共 %d 处（扫描 %d 个文件，用时 %.1f 秒）" % (
            where, pattern, len(r["files"]), sum(c for _, c in r["files"]), r["scanned"], r["seconds"])
    else:
        head = "在 %s 里搜索“%s”：找到 %d 条，在 %d 个文件里（扫描 %d 个文件，用时 %.1f 秒）" % (
            where, pattern, len(r["hits"]), len(r["files"]), r["scanned"], r["seconds"])
    if r["stop"]:
        head += "。已提前停止：%s，结果可能不全，可以用 folder 缩小范围" % r["stop"]
    lines = [head]
    if r.get("encrypted_only"):
        lines.append("仅搜索加密文件；明文文件请用普通搜索工具。")
    if r.get("skipped_plain"):
        lines.append("已跳过 %d 个明文文件：%s%s" % (len(r["skipped_plain"]),
                     "，".join(r["skipped_plain"][:10]), "……" if len(r["skipped_plain"]) > 10 else ""))
    if r["files_only"]:
        lines += ["%s（%d 处）" % fc for fc in r["files"]]
    else:
        # 按文件分组：路径只写一次，下面是“行号: 内容”
        last = None
        for rel, n, text in r["hits"]:
            if rel != last:
                lines.append(rel)
                last = rel
            lines.append("  %d: %s" % (n, text))
    if r["skipped_libs"]:
        shown = r["skipped_libs"][:5]
        more = " 等 %d 个" % len(r["skipped_libs"]) if len(r["skipped_libs"]) > 5 else ""
        lines.append("（跳过了厂家库目录：%s%s。要搜这些目录请用 folder 指定）" % ("，".join(shown), more))
    if r["unreadable"]:
        shown = r["unreadable"][:10]
        more = "等 %d 个" % len(r["unreadable"]) if len(r["unreadable"]) > 10 else ""
        lines.append("（编码无法识别、没有搜索的文件：%s%s）" % ("，".join(shown), more))
    return "\n".join(lines)


def _fmt_read(r):
    lines = [
        "完整路径：%s" % r["real"],
        "编码：%s  行尾：%s  总行数：%d" % (r["encoding"], r["eol"], r["total"]),
        "sha256：%s" % r["sha256"],
    ]
    if r["end"] >= r["start"]:
        lines.append("第 %d–%d 行：" % (r["start"], r["end"]))
        lines.append(r["body"])
    if r["note"]:
        lines.append("（%s）" % r["note"])
    return "\n".join(lines)


def _fmt_review_file(rv, what):
    lines = []
    if rv["file"]:
        lines.append("%s已保存给项目负责人查看%s：%s" % (what, "，已打开" if rv["opened"] else "", rv["file"]))
    if rv["note"]:
        lines.append("（%s）" % rv["note"])
    return lines


def _fmt_prepare(r, rv):
    enc = r["enc_before"] if r["enc_before"] == r["enc_after"] else "%s → %s" % (r["enc_before"], r["enc_after"])
    add, rem = _diff_counts(r["diff"])
    lines = [
        "修改编号：%s" % r["edit_id"],
        "完整路径：%s" % r["real"],
        "编码：%s" % enc,
        "修改范围：%s（diff +%d -%d 行）" % (_ranges_text(r["ranges"]), add, rem),
    ]
    if r["note"]:
        lines.append("说明：%s" % r["note"])
    lines += _fmt_review_file(rv, "diff ")
    if rv["inline"]:
        lines += ["```diff", _cap_lines(r["diff"], INLINE_DIFF_MAX_LINES), "```"]
    return "\n".join(lines)


def _fmt_new(r, rv):
    how = ("新建文件（受信任 Python 新建的文件是明文，不加密）" if r["mode"] == "create"
           else "写入已有的空文件（保持这个文件原来的加密状态）")
    lines = [
        "修改编号：%s" % r["edit_id"],
        "完整路径：%s" % r["real"],
        "方式：%s" % how,
        "编码：%s，行尾 %s，共 %d 行" % (r["encoding"], r["eol"], r["lines"]),
    ]
    lines += _fmt_review_file(rv, "内容")
    if rv["inline"]:
        lines += ["预览（前 20 行）：", r["preview"]]
    return "\n".join(lines)


def _fmt_commit(r, prepared=None, review=None):
    if r["before"] is None:
        encryption = _enc_word(r["after"]["encrypted"] if r["after"] else None)
    else:
        encryption = "%s→%s" % (_enc_word(r["before"]["encrypted"]), _enc_word(r["after"]["encrypted"]))
    encoding = r["enc_after"]
    if r["enc_before"] and r["enc_before"] != r["enc_after"]:
        encoding = "%s→%s" % (r["enc_before"], r["enc_after"])
    lines = [
        "写回成功：%s" % r["real"],
        "编号：%s | 行：%s | 编码：%s" % (r["edit_id"], _ranges_text(r["ranges"]), encoding),
        "内容核对：通过 | 加密：%s" % encryption,
        "sha256：%s" % r["sha256"],
        "备份：%s" % (r["backup"] or "无（新文件）"),
    ]
    if r["mode"] == "create":
        lines.append("提示：新文件是明文；需要加密时由人工在 Keil 中保存。")
    if r["warning"]:
        lines.append("注意：%s" % r["warning"])
    if review:
        if review["note"]:
            lines.append("注意：%s" % review["note"])
        # 默认仅返回一次写回结果；显式 show_diff 或配置要求时仍返回差异。
        if review["inline"] and prepared is not None:
            if prepared.get("preview") is not None:
                lines += ["预览（前 20 行）：", prepared["preview"]]
            else:
                lines += ["```diff", _cap_lines(prepared["diff"], INLINE_DIFF_MAX_LINES), "```"]
    return "\n".join(lines)


def _fmt_log(title, entries):
    if not entries:
        return "%s没有修改记录。" % title
    lines = ["%s的修改记录（共 %d 条）：" % (title, len(entries)), ""]
    for e in entries:
        ranges = [tuple(x) for x in (e.get("ranges") or [])]
        lines.append("- `%s`（%s）" % (e.get("file"), e.get("time", "").replace("T", " ")))
        content = "修改内容：%s" % (_ranges_text(ranges) if ranges else "（无行号信息）")
        if e.get("mode") == "create":
            content = "修改内容：新建文件"
        if e.get("note"):
            content += "；说明：%s" % e["note"]
        lines.append("  - " + content)
        if e.get("result") == "ok":
            enc = e.get("encoding_after") or ""
            if e.get("encoding_before") and e.get("encoding_before") != e.get("encoding_after"):
                enc = "%s → %s" % (e.get("encoding_before"), e.get("encoding_after"))
            lines.append("  - 结果：成功；编码 %s；加密：%s → %s" % (
                enc, _enc_word(e.get("encrypted_before")), _enc_word(e.get("encrypted_after"))))
        else:
            lines.append("  - 结果：失败（%s）" % e.get("error", ""))
        if e.get("backup"):
            lines.append("  - 备份：%s" % e["backup"])
    return "\n".join(lines)
