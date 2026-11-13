# safe_edit 部署与使用

## 部署

1. 阅读 README.md，确认目标 MCP 客户端、授权项目目录、备份目录和受本机透明加密策略信任的 Python 3.12 路径。用实际路径替换示例。
2. 从 config.example.json 生成本机 config.json。若已有 config.json，保留本机设置并只调整部署所需的字段。备份目录应独立、可写并限制访问。保留白名单的项目范围。
3. 按 README.md 合并对应客户端的 safe_edit 条目，保留其他服务和原有权限设置。把 SAFE_EDIT_ROOT 设为授权项目目录。
4. 重启或重开客户端后调用 get_status，确认版本、白名单、工作目录、备份目录和锁定状态，再对用户授权的已知加密样本调用 check_file。报告结果及仍需用户完成的步骤。接入检查只做读取和检测。

## 使用

- get_status 核对范围和锁状态。check_file 先检测目标，单个文件用 path，批量用 paths（1–50 个）。use_safe_edit=false 时使用普通工具并保持编码和行尾。
- 加密文件先用 search_code 定位，再用 read_source 按行读取相关范围。
- 已授权的加密文件改动使用 prepare_edit。旧内容须唯一。按行号修改需要 base_sha256 和行内容锚点。默认备份并直接写回，dry_run=true 用于只预览，commit_edit 用于提交预览。
- prepare_new_file 只填充已经存在的加密空文件。用普通工具创建不存在的目标。
- 遇到检测错误或锁定时停止写入，报告原始错误。通过 change_log 查询写回记录。
