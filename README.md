# ZCode 泄漏自检（Zcode_leak_self_check）

> **原始排查文章**：[ZCode 静默工作区快照上传](https://blog.ferstar.org/posts/zcode-silent-workspace-snapshot-upload/)  
> 本仓库把该文描述的现象，固化成可复现的 **本地自检 skill**，并给出「夯→拉」泄漏排名报告。

---

## 怎么使用这个 Skill

### 方式 A：MiMo Desktop / MiMoCode（推荐）

1. 把 skill 目录拷到全局技能路径（目录名即技能 ID）：

```bash
mkdir -p ~/.config/mimocode/skills
cp -R skills/zcode-leak-audit ~/.config/mimocode/skills/
```

2. **新开一个对话**（新建技能需新会话才会被扫描加载）。
3. 对助手说任一句：

   - `用 zcode-leak-audit 查一下本机 ZCode 有没有泄漏`
   - `生成 zcode 泄漏排名报告（夯到拉）`
   - `检查一下 ~/.zcode 为什么占了这么多空间`

4. 助手会按 `SKILL.md` 流程：只读取证 → 评分 → 生成 `index.html`。

### 方式 B：不装 Skill，直接跑脚本

```bash
# 1) 采集本机证据（只读）
python3 skills/zcode-leak-audit/scripts/audit_zcode.py \
  --json /tmp/zcode-audit.json

# 2) 生成夯→拉排名 HTML 报告
python3 skills/zcode-leak-audit/scripts/render_report.py \
  --input /tmp/zcode-audit.json \
  --output ./index.html
```

有 MiMo Desktop 时可用 `"$MIMO_PYTHON"` 代替 `python3`。

### 方式 C：人工对照取证

脚本不可用时，按 [`skills/zcode-leak-audit/references/evidence-checklist.md`](skills/zcode-leak-audit/references/evidence-checklist.md) 用 `du` / `find` / `cat` 手工采集，再对照评分细则出结论。

### 输出长什么样

- **整机器位**：夯 / 很夯 / 有点夯 / 一般 / 偏拉 / 拉  
- **工作区排名表**：按泄漏程度 **夯（最重）→ 拉（最轻）**  
- **证据卡**：pending 体积、`.git` 占比、RSA 信封、开关是否失效、全局配置外带  
- **防御**：锁 `~/.zcode/v2/checkpoints`

示例数据见 [`examples/zcode-audit.sample.json`](examples/zcode-audit.sample.json)。

### 评分速查（夯→拉）

| 分数 | 档位 | 含义 |
|-----:|------|------|
| ≥70 | 夯 | 大包 + Git 历史 + 服务端独钥 + 开关失效 |
| 50–69 | 很夯 | 存在加密 pending 或明显 `.git` 入包 |
| 35–49 | 有点夯 | 有快照痕迹但范围/体积有限 |
| 20–34 | 一般 | 仅小快照或无 `.git` |
| 1–19 | 偏拉 | 仅 schema/日志痕迹 |
| 0 | 拉 | 干净 / 未见产物 |

细则见 [`references/ranking.md`](skills/zcode-leak-audit/references/ranking.md)。

### 一键防御（macOS）

```bash
rm -rf ~/.zcode/v2/checkpoints
mkdir -p ~/.zcode/v2/checkpoints
chflags uchg ~/.zcode/v2/checkpoints
touch ~/.zcode/v2/checkpoints/test   # 应报 Operation not permitted
```

解除：`chflags nouchg ~/.zcode/v2/checkpoints`  
Linux：`sudo chattr +i / -i ~/.zcode/v2/checkpoints`

---

## 背景：文章在说什么

在登录态下，ZCode（智谱官方 AI 编程桌面端）会在后台对打开过的工作区做快照：

1. 扫描工作区，生成 **Manifest 文件清单**（可含完整 `.git`）  
2. 本地 `tar.gz` → **AES-256-CTR** 加密 → 用服务端下发的 **RSA-OAEP-SHA256** 公钥封装对称密钥  
3. 产物落在 `~/.zcode/v2/checkpoints/**/pending/*.tar.gz.enc`  
4. 携带 `uploadCredentialHandle` 上传（目标链路指向阿里云 OSS 一类对象存储；协调端点为 `zcode.z.ai`）  
5. UI 中相关开关关闭时，打包与重试仍可能发生

本机复现结论：**机制真实存在**；密文本地无私钥，用户与客户端本体都解不开。

---

## 打包时会「筛选」什么？（重要）

自检时不要假设「系统会智能判断什么重要、不传敏感内容」。根据客户端常量与本机 Manifest/密文对照，更准确的图景是：

### 会排除的（路径黑名单，机械过滤）

技能扫描 / 目录遍历里可见类似排除集：

```text
node_modules, dist, build, out, target, vendor,
coverage, .cache, .next, .turbo, .venv, __pycache__
```

- Manifest 中 **通常看不到 `node_modules`**  
- 这是 **依赖与构建产物黑名单**，不是「商业机密识别」

### 不会被当成「不重要」而挡掉的（高风险）

只要仓库被扫进 baseline，下列内容可能进清单，打包成功时甚至进密文：

| 内容 | 本机观察 |
|------|----------|
| `.git/objects`（完整提交历史） | threejs-arena 中占清单 **93%** |
| `.git/config`（内网远端等） | 出现在 manifest |
| `.git/logs`（reflog） | 出现在 manifest |
| 业务源码 / 配置 | `src`、`packages`、脚本等 |
| 全局 Agent 配置 | `hooks.json` / `mcp.json` / `settings.behavior.json` / `skills.json`（extra-manifest） |
| 会话附件 | extra-manifest 中可见 `prompt-attachment` |

另有敏感路径判断（`.git`、`.claude`、`hooks`…）用于 **memory 文件** 场景，**并未同等用于 repo snapshot**。

### 「清单全量」≠「密文全量」

| 工作区类型 | 清单 | 密文倾向 |
|------------|------|----------|
| 带 `.git` 且打包成功 | 全量台账 | 密文/清单可达 **0.8～0.95**（整包） |
| 大结果集 / 数据目录多 | 仍列全文件 | 密文可能极小（失败重试、限额、增量未完成） |
| 无 `.git` 小项目 | 列业务文件 | 视触发与打包结果而定 |

客户端 schema 还包含 `repo_snapshot_prompt`、`delta`、`extra_delta`、`upload_key`、`upload_target`，说明存在 **baseline / 增量 / 上传凭证** 管线；extra-manifest 里 `changePolicy: rare` 管的是全局配置 **重传频率**，不是重要性裁决。

### 触发点（何时会抓）

`state.json` 中常见：

- `captureStage`: `prompt`（发提示词前） / `terminal`（任务结束）  
- `kind`: `baseline`  
- `failureCount`: 上传失败重试次数（本机可见上百次）

### 一句话结论

```text
有筛选：依赖/构建目录黑名单 + 体积/失败/增量约束
无证据：语义级「重要性模型」在保护密钥与 Git 历史
风险假设：核心资产进了 baseline，就应按可能出网处理
```

---

## 仓库结构

```text
Zcode_leak_self_check/
├── README.md
├── skills/zcode-leak-audit/
│   ├── SKILL.md                 # 技能入口（触发词 + 审计流程）
│   ├── scripts/
│   │   ├── audit_zcode.py       # 只读采集器
│   │   └── render_report.py     # 夯→拉 HTML 报告
│   ├── references/
│   │   ├── evidence-checklist.md
│   │   └── ranking.md
│   └── locales/
│       ├── zh-CN.json
│       └── en-US.json
└── examples/
    └── zcode-audit.sample.json  # 样例取证数据（已脱敏）
```

## Skill 里有什么

| 文件 | 作用 |
|------|------|
| `SKILL.md` | 何时触发、取证步骤、评分、出报告、防御 |
| `audit_zcode.py` | 扫描 `~/.zcode`、checkpoints、envelope、manifest、开关、客户端信号 |
| `render_report.py` | 生成移动端可读的夯→拉排名报告 |
| `references/*` | 手工清单与评分细则 |

### 采集的证据类型

- `~/.zcode` / `v2/checkpoints` 体积  
- `pending/*.tar.gz.enc` 与 `*.envelope.json`（算法、encryptedDataKey）  
- `state.json`（workspace、baseline、failureCount、uploadCredentialHandle、captureStage）  
- Manifest 构成（文件数、`.git` 占比、目录分布）  
- extra-manifest（全局配置外带）  
- `setting.json` 开关（`optimizeAgentExperienceEnabled` / `repoSnapshotIndexingEnabled`）  
- 客户端 `zcode.cjs` 中的 `repo_snapshot_*` schema 与端点常量  

**报告不会输出 API Key 明文。** 若 `provider_config.json` 等含凭据，只提示文件存在。

## 边界与免责

- 本工具 **只读自检**，不上传、不修改你的项目代码。  
- 本机可直接证明：静默打包、服务端公钥加密、清单可含 Git 历史、开关可能管不住快照。  
- 「成功 POST 到对象存储」若无抓包/服务端回执，只记为间接证据（凭证句柄 + 重试计数）。  
- 使用本工具产生的结论由使用者自行判断；对厂商行为的最终认定以官方披露与司法/合规渠道为准。  
- 原始现象描述与排查过程版权归原博文作者；本仓库是社区自检工具化。

## License

建议以 MIT 发布（可自行在仓库中补充 `LICENSE`）。引用博文时请保留出处链接。

---

**相关链接**

- 原文：https://blog.ferstar.org/posts/zcode-silent-workspace-snapshot-upload/  
- 本仓库：https://github.com/suyoumo/Zcode_leak_self_check
