# safe_edit 1.5.0

适用于 Windows 透明加密环境的 MCP 服务和命令行工具。先检查加密状态，再搜索、按行读取或修改加密文件。写回时会备份，并检查写入内容和加密状态。Python 代码只依赖标准库。

## 交给 AI 部署

克隆仓库，把下面这段发给能在本机操作文件和终端的 AI。

```text
请阅读仓库内的 AGENTS.md 和 README.md，按步骤在本机部署 safe_edit。
目标客户端是【Codex / Claude Code】，项目目录是【本机项目的绝对路径】。
请使用本机透明加密策略已授权的 Python 3.12，配置项目白名单和独立备份目录。
接入后只用 get_status 和 check_file 检查配置与授权样本，并告诉我结果。
```

```powershell
git clone https://github.com/p516757794/safe_edit.git
```

已经克隆时，在该仓库目录执行 git pull。下文用 C:\Tools\safe_edit 表示工具目录，请替换为实际克隆路径。

## Windows 环境与配置

1. 找到本机透明加密策略信任的 Python 3.12 可执行文件。工具依赖 Python 读取授权明文，同时依赖 Windows PowerShell 5.1 读取同一文件的磁盘原始字节。若无法确认策略，向本机加密环境管理员核实。
2. 把 config.example.json 复制为同目录的 config.json。将 backup_root 改为本机受控、可写的绝对目录。该目录存放备份、差异、审计日志和锁文件，其中差异可能包含源码。JSON 路径使用双反斜杠。
3. whitelist_root 默认留空。此时工作目录就是白名单，MCP 通过 SAFE_EDIT_ROOT 指向授权项目目录，CLI 通过 --root 指定。工具目录和备份目录自动排除。deny_read 可填入要禁止 AI 读取的路径或通配符。
4. 使用下面对应客户端的配置。请替换解释器、脚本和项目目录三个示例路径。配置修改后重新打开客户端或重启 MCP 服务。

## Codex

合并到用户目录下的 .codex\config.toml 中。如果已有同名服务，只更新对应条目。

```toml
[mcp_servers.safe_edit]
command = 'C:\Path\To\TrustedPython\python.exe'
args = ['C:\Tools\safe_edit\safe_edit_server.py']
env = { SAFE_EDIT_ROOT = 'D:\Work\MyProject' }
```

## Claude Code

合并到目标项目目录的 .mcp.json 中。如果文件已有配置，请保留其他服务。打开项目时按客户端提示批准此项目的 MCP 服务。

```json
{
  "mcpServers": {
    "safe_edit": {
      "type": "stdio",
      "command": "C:\\Path\\To\\TrustedPython\\python.exe",
      "args": ["C:\\Tools\\safe_edit\\safe_edit_server.py"],
      "env": { "SAFE_EDIT_ROOT": "D:\\Work\\MyProject" }
    }
  }
}
```

其他 stdio MCP 客户端也可以用同一个 Python 作为 command、服务脚本绝对路径作为 args，并设置 SAFE_EDIT_ROOT。

## 接入检查

- 在客户端调用 get_status，核对版本 1.5.0、工作目录、白名单、备份目录和锁定状态。
- 用 check_file 检查一份已知加密的授权样本。预期为 use_safe_edit=true。检测结果与样本预期不符时，核对 Python、PowerShell 和加密策略后再尝试。
- CLI 可以完成相同的只读检查。

```powershell
$trustedPython = 'C:\Path\To\TrustedPython\python.exe'
$cliPath = 'C:\Tools\safe_edit\safe_edit_cli.py'
$projectPath = 'D:\Work\MyProject'
& $trustedPython $cliPath --root $projectPath status
& $trustedPython $cliPath --root $projectPath check 'Function\Example.c'
```

需要验证加密写回时，由有权限的人员在隔离目录对样本副本运行 selftest.py。--sample 指向授权样本，--dir 指向受同一加密策略保护且尚不存在的临时目录。

## 日常使用

先调用 get_status，再用 check_file 检查目标。明文或不存在的文件用普通工具处理。加密文件用 search_code、read_source 和 prepare_edit。已授权的修改默认直接备份并写回，dry_run=true 用于只预览。发生检测错误或写回锁定时，停止写入并报告原始错误。详见 AGENTS.md。

## 在 Codex 中启用 AI 产品经理设定

仓库提供一份独立的 [AI 产品经理工作手册](templates/codex/product-manager/AGENTS.md)，包含需求确认、任务下达、静态审核和 safe_edit 操作约定。

1. 在 safe_edit 仓库中执行 `git pull`，然后把模板复制到**目标业务项目的根目录**，文件名为 `AGENTS.md`。
2. 如果项目已有 `AGENTS.md`，将手册合并到现有文件，保留项目约定并处理冲突。同一目录如果已有 `AGENTS.override.md`，Codex 会优先加载它，此时将手册合并到实际生效的文件。
3. 在 Codex 中打开目标业务项目并新建会话。可让 Codex 概述当前角色、审批规则和 safe_edit 约定，确认已读到手册。加载规则见 [OpenAI 官方文档](https://learn.chatgpt.com/docs/agent-configuration/agents-md)。

也可以在 safe_edit 仓库打开 Codex，把下面这段交给它执行。

```text
请把 templates/codex/product-manager/AGENTS.md 接入目标业务项目【绝对路径】。
项目已有 AGENTS.md 或 AGENTS.override.md 时，先查看并保留现有约定，再合并到 Codex 实际加载的文件。
完成后告诉我写入了哪个文件。我会在目标业务项目里开启新会话。
```

手册中的 safe_edit 调用需要先完成上面的 MCP 接入。第五节适用于透明加密文件，第六节针对使用 Keil ARMCC 5 的项目。
