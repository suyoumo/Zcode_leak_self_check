# 手工取证清单（脚本不可用时）

只读操作。不要上传任何文件。

## 1. 体积

```bash
du -sh ~/.zcode ~/.zcode/v2/checkpoints 2>/dev/null
find ~/.zcode/v2/checkpoints -type f -exec ls -la {} \; 2>/dev/null | sort -k5 -n | tail
```

## 2. pending 加密包

```bash
find ~/.zcode/v2/checkpoints -name '*.tar.gz.enc' 2>/dev/null
find ~/.zcode/v2/checkpoints -name '*.envelope.json' -exec cat {} \; 2>/dev/null
```

关注字段：`schema`, `contentAlgorithm`, `keyWrapAlgorithm`, `encryptedDataKey`, `keyId`

## 3. state.json

```bash
for f in ~/.zcode/v2/checkpoints/*/state.json; do echo "==== $f"; cat "$f"; done
```

关注：`workspacePath`, `encryptedSizeBytes`, `kind: baseline`, `failureCount`,
`uploadCredentialHandle`, `captureStage`

## 4. Manifest 构成

```bash
# 体积最大的 manifest
find ~/.zcode/v2/checkpoints -path '*/manifests/*.json' -exec ls -la {} \; | sort -k5 -n | tail
```

统计 `files[].path` 中 `.git/` 的 `sizeBytes` 占比。

## 5. 全局配置外带

```bash
find ~/.zcode/v2/checkpoints -path '*/extra-manifests/*.json' -exec cat {} \; 2>/dev/null
```

关注 `groupId: global-configs` 与 `app-memory:*`。

## 6. 设置开关

```bash
cat ~/.zcode/v2/setting.json
```

关注 `optimizeAgentExperienceEnabled`、`repoSnapshotIndexingEnabled`。

## 7. 客户端常量（可选）

```bash
strings /Applications/ZCode.app/Contents/Resources/glm/zcode.cjs 2>/dev/null \
  | rg -n "repo_snapshot|zcode.z.ai|repoSnapshotIndexing|optimizeAgentExperience" | head
```

## 8. 禁止写入报告的内容

- provider_config.json / credentials.json 中的 API Key、token 明文
- 完整企业内网地址若用户未要求脱敏时，可保留域名，但不要输出密钥
