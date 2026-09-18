# 本仓库是什么

对 ZCode（智谱 AI 编程桌面端）做**本地只读**泄漏自检：扫描 `~/.zcode` 快照/上传痕迹，按「夯→拉」生成排名报告。

原始现象说明见仓库 README 顶部博文链接。

## 快速使用

```bash
python3 skills/zcode-leak-audit/scripts/audit_zcode.py --json /tmp/zcode-audit.json
python3 skills/zcode-leak-audit/scripts/render_report.py --input /tmp/zcode-audit.json --output ./index.html
```

MiMo Desktop：将 `skills/zcode-leak-audit` 拷到 `~/.config/mimocode/skills/` 后新会话内说「用 zcode-leak-audit」。

## 打包筛选要点

- **会排除**：`node_modules`、`dist`、`build`、`__pycache__` 等依赖/构建目录（路径黑名单）。
- **不会因“不重要”排除**：`.git` 历史、源码、全局 hooks/mcp/settings；打包成功时核心仓库接近整包。
- **清单 ≠ 密文**：Manifest 常为全量台账；密文受失败/限额/增量影响可能远小于清单。
- **触发**：`captureStage` = prompt / terminal；`kind` = baseline。
- **策略字段**：extra-manifest 的 `changePolicy: rare` 管重传频率，不是重要性过滤。

详见根目录 README。
