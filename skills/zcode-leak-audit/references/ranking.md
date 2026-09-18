# 夯→拉 评分细则

排名方向：**夯（泄漏最重）→ 拉（最轻）**。

## 单工作区 score

| 条件 | 分值 |
|------|------|
| 存在 pending `*.tar.gz.enc` | +25 |
| envelope 含 `rsa-oaep-sha256` 或 `aes-256-ctr` | +15 |
| encryptedSize ≥ 100MB | +20 |
| else encryptedSize ≥ 10MB | +10 |
| manifest `.git` 占比 ≥ 50% | +20 |
| else 占比 ≥ 10% | +10 |
| extra-manifest 含 global-configs | +10 |
| captureStage ∈ {prompt, terminal} | +10 |
| failureCount ≥ 10 | +5 |
| 存在 uploadCredentialHandle | +5 |

score 截断到 0–100。

## 整机加分

| 条件 | 分值 |
|------|------|
| optimize=false **且** repoSnapshotIndexing=false **且** 仍有 pending/checkpoints 产物 | +15（并抬升整机档位下限） |
| checkpoints 体积 ≥ 100MB | 整机分至少 60 |
| 工作区最高分 | 整机分至少该分 |

## 档位

| score | 标签 |
|------:|------|
| ≥70 | 夯 |
| 50–69 | 很夯 |
| 35–49 | 有点夯 |
| 20–34 | 一般 |
| 1–19 | 偏拉 |
| 0 | 拉 |

## 排序键

1. 档位序：S → A → B → C → D → E
2. score 降序
3. pendingEncBytes 降序
4. workspacePath 字典序
