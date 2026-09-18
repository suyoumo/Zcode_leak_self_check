---
name: zcode-leak-audit
description: 对本机 ZCode（智谱 AI 编程桌面端）做静默工作区快照/泄漏取证审计，扫描 ~/.zcode 与客户端产物，按泄漏程度从「夯」到「拉」排名，并生成可预览的 HTML 总结报告。Use when the user asks to audit ZCode for silent snapshot/code leakage, check ~/.zcode disk usage, rank leak severity 夯到拉, or generate a zcode leak HTML report. 当用户提到「ZCode 泄漏」「zcode 快照上传」「~/.zcode 占空间」「检查 zcode 有没有偷传代码」「生成泄漏排名报告」「zcode-leak-audit」「夯到拉」时使用。不要用于一般磁盘清理或与 ZCode 无关的隐私审计。
---

# ZCode 泄漏审计（夯→拉）

对本机 ZCode 做只读取证：确认是否存在「登录后静默打包工作区（含 .git）→ 服务端 RSA 信封加密 → pending 待上传」链路，并输出按泄漏严重度排名的 HTML 报告。

## Important

- **只读**：不要上传、外传或修改被审计项目的源码。可读 `~/.zcode`、`ZCode.app`、日志、设置。
- **勿把密钥写入报告**：若读到 `provider_config.json` 等含 API Key 的文件，报告中只写「存在凭据文件」，不得粘贴密钥明文。
- **报告路径**：默认写到当前工作目录 `index.html`；用户指定路径时用用户路径。
- **排名方向**：泄漏程度 **夯（最重）→ 拉（最轻）**，不是反过来。

## 触发后的标准流程

### Step 1 — 确认安装与数据根

```bash
ls -la ~/.zcode 2>/dev/null || echo NO_ZCODE
ls -la /Applications/ZCode.app 2>/dev/null || ls -la ~/Applications/ZCode.app 2>/dev/null
du -sh ~/.zcode ~/.zcode/cli ~/.zcode/computer-use ~/.zcode/v2 2>/dev/null
du -sh ~/.zcode/v2/checkpoints 2>/dev/null
```

若无 `~/.zcode` 且无 `ZCode.app`：结论为「本机未安装 / 无数据」，生成「拉」级空报告即可。

### Step 2 — 采集证据（优先跑脚本）

优先执行内置采集器（确定性、可复现）：

```bash
"$MIMO_PYTHON" ~/.config/mimocode/skills/zcode-leak-audit/scripts/audit_zcode.py --json /tmp/zcode-audit.json
```

无 `MIMO_PYTHON` 时用系统 `python3`。

脚本会采集：

| 证据 | 路径/来源 | 泄漏含义 |
|------|-----------|----------|
| checkpoints 体积 | `~/.zcode/v2/checkpoints` | 本地滞留的快照产物 |
| pending 加密包 | `**/pending/*.tar.gz.enc` | 已打包待传的工作区 |
| 信封算法 | `*.envelope.json` | 是否服务端 RSA 独钥 |
| 工作区状态 | `*/state.json` | baseline、失败重试、凭证句柄 |
| Manifest 构成 | `*/manifests/*.json` | `.git` 历史是否入包 |
| 全局配置外带 | `**/extra-manifests/*.json` | hooks/mcp/settings/skills |
| UI 开关 | `~/.zcode/v2/setting.json` | 开关是否管不住快照 |
| 客户端 schema | `ZCode.app/.../zcode.cjs` | `repo_snapshot_*` 常量 |
| 端点 | 同上 + 日志 | `zcode.z.ai` 等 |

脚本若不可用，按 `references/evidence-checklist.md` 手工用 `find`/`cat`/`du` 补齐，结果同样整理成 JSON。

### Step 3 — 评分与排名（夯→拉）

评分模型（脚本已内置，手工审计时对齐同一套分）：

**单工作区 score（0–100）**

- +25 存在 pending `.tar.gz.enc`
- +15 envelope 为 `rsa-oaep-sha256` / `aes-256-ctr`
- +20 encryptedSize ≥ 100MB；+10 若 ≥ 10MB
- +20 manifest 中 `.git` 占比 ≥ 50%；+10 若 ≥ 10%
- +10 extra-manifest 含 `global-configs`
- +10 captureStage ∈ {prompt, terminal}
- +5 failureCount ≥ 10
- +5 存在 `uploadCredentialHandle`

**整机加分**

- +15 `optimizeAgentExperienceEnabled=false` 且 `repoSnapshotIndexingEnabled=false`，但仍存在 pending/checkpoints（开关失效）

**档位**

| 分数 | 排名标签 | 解读 |
|------|----------|------|
| ≥70 | 夯 | 极高：大包 + Git 历史 + 服务端独钥 + 开关失效 |
| 50–69 | 很夯 | 高：存在加密 pending 或明显 .git 入包 |
| 35–49 | 有点夯 | 中高：有快照痕迹但体积/范围有限 |
| 20–34 | 一般 | 中：仅小快照或无 .git |
| 1–19 | 偏拉 | 低：仅 schema/日志痕迹 |
| 0 | 拉 | 极低/干净 |

多个工作区按 score **降序**输出（夯在前，拉在后）。

### Step 4 — 生成 HTML 报告

```bash
"$MIMO_PYTHON" ~/.config/mimocode/skills/zcode-leak-audit/scripts/render_report.py \
  --input /tmp/zcode-audit.json \
  --output ./index.html
```

报告必须包含：

1. **总判**：本机是否存在该问题 + 整机档位
2. **夯→拉排名表**：工作区、score、档位、关键证据、pending 体积、`.git` 占比
3. **证据卡片**：envelope 摘要、开关状态、全局配置清单
4. **边界**：直接证明 vs 未抓包证明
5. **防御**：`chflags uchg` / `chattr +i` 锁 `~/.zcode/v2/checkpoints`

生成后把 `index.html` 用 `present_files` 交给用户（若在 MiMo Desktop 中）。

### Step 5 — 口头摘要

用 3–6 句中文收口：

- 整机档位（夯/很夯/…）
- 最严重的 1–3 个工作区及原因
- 开关是否失效
- 建议防御动作

## 输出物

- `index.html` — 移动端可读的泄漏排名报告（夯→拉）
- 可选 `/tmp/zcode-audit.json` — 原始取证数据（不要当交付物炫耀，除非用户要）

## Examples

| 用户说 | 你要做 |
|--------|--------|
| 「帮我查一下 ZCode 有没有泄漏问题」 | 走完整流程 Step 1–5 |
| 「生成 zcode 泄漏排名报告」 | 已有 JSON 则直接 render；没有先 audit |
| 「~/.zcode 为什么几百 MB」 | 重点展示 checkpoints/pending 排名 |
| 「用 zcode-leak-audit」 | 本技能；同样走 Step 1–5 |
| 「清理一下磁盘」 | 不要默认用本技能；除非用户点名 ZCode 快照 |

## Troubleshooting

| 现象 | 处理 |
|------|------|
| `audit_zcode.py` 报无 `~/.zcode` | 报告整机「拉」；说明未安装或数据已清 |
| manifest 极大（>10MB） | 脚本流式/限制统计 top 目录，避免内存爆 |
| 日志含 ENOTFOUND | 在报告「边界」写清：打包已证实，成功上传未在本机抓包 |
| 报告密钥风险 | 只提示 `provider_config.json` 存在，绝不贴 key |
| 技能未出现在对话 | 新建技能需新会话加载；检查是否写在 `~/.config/mimocode/skills/zcode-leak-audit/` |

## 相关文件

- `scripts/audit_zcode.py` — 采集器
- `scripts/render_report.py` — 排名 HTML 生成器（样式已内联，无独立 css 依赖）
- `references/evidence-checklist.md` — 手工取证清单
- `references/ranking.md` — 评分细则
