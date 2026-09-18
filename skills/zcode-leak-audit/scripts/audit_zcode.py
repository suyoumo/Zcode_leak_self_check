#!/usr/bin/env python3
"""ZCode local leak forensics collector (read-only)."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

HOME = Path.home()
ZCODE = HOME / ".zcode"
CHECKPOINTS = ZCODE / "v2" / "checkpoints"
SETTING = ZCODE / "v2" / "setting.json"
APP_CJS = Path("/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs")


def human(n: int) -> str:
    f = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if f < 1024 or u == "GB":
            return f"{f:.1f}{u}" if u != "B" else f"{int(f)}B"
        f /= 1024
    return f"{f:.1f}GB"


def dir_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    for root, _dirs, files in os.walk(path):
        for name in files:
            fp = Path(root) / name
            try:
                total += fp.stat().st_size
            except OSError:
                pass
    return total


def parse_manifest_stats(mf: Path, limit_files: int = 200000) -> dict:
    try:
        data = json.loads(mf.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        return {"error": str(e), "path": str(mf)}
    files = data.get("files") or []
    git = src = 0
    cats: Counter[str] = Counter()
    for item in files[:limit_files]:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "")
        size = int(item.get("sizeBytes") or 0)
        if path.startswith(".git/") or path == ".git":
            git += size
            if path.startswith(".git/objects"):
                cats[".git/objects"] += size
            elif path.startswith(".git/lfs"):
                cats[".git/lfs"] += size
            elif path.startswith(".git/logs"):
                cats[".git/logs"] += size
            else:
                cats[".git/other"] += size
        else:
            src += size
    total = git + src
    return {
        "schema": data.get("schema"),
        "workspaceKey": data.get("workspaceKey"),
        "fileCount": len(files),
        "gitBytes": git,
        "srcBytes": src,
        "totalBytes": total,
        "gitRatio": round(git / total, 4) if total else 0.0,
        "topCats": cats.most_common(8),
        "path": str(mf),
    }


def parse_envelope(env: Path) -> dict:
    try:
        data = json.loads(env.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        return {"error": str(e), "path": str(env)}
    return {
        "schema": data.get("schema"),
        "contentAlgorithm": data.get("contentAlgorithm"),
        "keyWrapAlgorithm": data.get("keyWrapAlgorithm"),
        "keyId": data.get("keyId"),
        "hasEncryptedDataKey": bool(data.get("encryptedDataKey")),
        "hasLocalPrivateKey": False,  # envelope never carries private key
        "aad": data.get("aad"),
        "path": str(env),
    }


def parse_extra_manifest(em: Path) -> dict:
    try:
        data = json.loads(em.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        return {"error": str(e), "path": str(em)}
    groups = data.get("groups") or []
    files = []
    global_configs = []
    for g in groups:
        gid = g.get("groupId") or ""
        for f in g.get("files") or []:
            rec = {
                "group": gid,
                "path": f.get("path"),
                "sizeBytes": f.get("sizeBytes"),
                "source": f.get("source"),
            }
            files.append(rec)
            if gid == "global-configs" or str(f.get("source") or "").startswith("app-memory:"):
                global_configs.append(rec)
    return {
        "schema": data.get("schema"),
        "files": files[:50],
        "globalConfigs": global_configs,
        "hasGlobalConfigs": bool(global_configs),
        "path": str(em),
    }


def score_workspace(rec: dict, switches_off_but_active: bool) -> dict:
    score = 0
    reasons = []
    enc = rec.get("encryptedSizeBytes") or 0
    git_ratio = rec.get("gitRatio") or 0
    fail = rec.get("failureCount") or 0

    if rec.get("pendingEnc"):
        score += 25
        reasons.append("存在 pending 加密包 (+25)")
    env = rec.get("envelope") or {}
    if env.get("keyWrapAlgorithm") == "rsa-oaep-sha256" or env.get("contentAlgorithm") == "aes-256-ctr":
        score += 15
        reasons.append("服务端 RSA/AES 信封 (+15)")
    if enc >= 100 * 1024 * 1024:
        score += 20
        reasons.append(f"密文 ≥100MB ({human(enc)}) (+20)")
    elif enc >= 10 * 1024 * 1024:
        score += 10
        reasons.append(f"密文 ≥10MB ({human(enc)}) (+10)")
    if git_ratio >= 0.5:
        score += 20
        reasons.append(f".git 占比 {git_ratio*100:.0f}% (+20)")
    elif git_ratio >= 0.1:
        score += 10
        reasons.append(f".git 占比 {git_ratio*100:.0f}% (+10)")
    if rec.get("extraHasGlobal"):
        score += 10
        reasons.append("外带全局配置 (+10)")
    if rec.get("captureStage") in {"prompt", "terminal"}:
        score += 10
        reasons.append(f"触发点 {rec.get('captureStage')} (+10)")
    if fail >= 10:
        score += 5
        reasons.append(f"failureCount={fail} (+5)")
    if rec.get("uploadCredentialHandle"):
        score += 5
        reasons.append("存在上传凭证句柄 (+5)")
    if switches_off_but_active and (rec.get("pendingEnc") or rec.get("checkpointBytes", 0) > 0):
        score += 15
        reasons.append("开关失效仍产出 (+15)")

    score = max(0, min(100, score))
    if score >= 70:
        band, label = "S", "夯"
    elif score >= 50:
        band, label = "A", "很夯"
    elif score >= 35:
        band, label = "B", "有点夯"
    elif score >= 20:
        band, label = "C", "一般"
    elif score >= 1:
        band, label = "D", "偏拉"
    else:
        band, label = "E", "拉"
    return {"score": score, "band": band, "label": label, "reasons": reasons}


def collect_client_signals() -> dict:
    sig = {
        "appInstalled": Path("/Applications/ZCode.app").exists(),
        "zcodeCjs": str(APP_CJS) if APP_CJS.exists() else None,
        "endpointHits": [],
        "schemaHits": [],
        "switchLogicNotes": [],
    }
    if not APP_CJS.exists():
        return sig
    try:
        text = APP_CJS.read_bytes()[: 12 * 1024 * 1024].decode("utf-8", errors="ignore")
        # full file may be larger; also scan rest in chunks if needed
        data = APP_CJS.read_bytes()
        text = data.decode("utf-8", errors="ignore")
    except Exception as e:
        sig["readError"] = str(e)
        return sig
    for pat in [
        r"https://zcode\.z\.ai",
        r"repo_snapshot_[a-z_]+",
        r"REPO_SNAPSHOT_[A-Z_]+",
        r"repoSnapshotIndexingEnabled",
        r"optimizeAgentExperienceEnabled",
    ]:
        hits = [m.group(0) for m in re.finditer(pat, text)]
        uniq = list(dict.fromkeys(hits))[:20]
        if "repo_snapshot" in pat or "REPO_SNAPSHOT" in pat:
            sig["schemaHits"].extend(uniq)
        elif "zcode.z.ai" in pat:
            sig["endpointHits"].extend(uniq)
        else:
            sig["switchLogicNotes"].extend(uniq)
    sig["schemaHits"] = list(dict.fromkeys(sig["schemaHits"]))[:30]
    sig["endpointHits"] = list(dict.fromkeys(sig["endpointHits"]))[:10]
    return sig


def collect() -> dict:
    now = datetime.now(timezone.utc).isoformat()
    result = {
        "generatedAt": now,
        "hostUser": os.environ.get("USER") or "",
        "zcodeRoot": str(ZCODE),
        "zcodeExists": ZCODE.exists(),
        "app": collect_client_signals(),
        "sizes": {
            "zcodeTotal": dir_size(ZCODE),
            "checkpoints": dir_size(CHECKPOINTS),
            "cli": dir_size(ZCODE / "cli"),
            "computerUse": dir_size(ZCODE / "computer-use"),
        },
        "settings": {},
        "workspaces": [],
        "global": {},
        "defense": {
            "macos": [
                "rm -rf ~/.zcode/v2/checkpoints",
                "mkdir -p ~/.zcode/v2/checkpoints",
                "chflags uchg ~/.zcode/v2/checkpoints",
                "touch ~/.zcode/v2/checkpoints/test  # expect Operation not permitted",
            ],
            "linux": [
                "sudo rm -rf ~/.zcode/v2/checkpoints && mkdir -p ~/.zcode/v2/checkpoints",
                "sudo chattr +i ~/.zcode/v2/checkpoints",
            ],
            "unlockMacos": "chflags nouchg ~/.zcode/v2/checkpoints",
            "unlockLinux": "sudo chattr -i ~/.zcode/v2/checkpoints",
        },
    }

    if SETTING.exists():
        try:
            st = json.loads(SETTING.read_text(encoding="utf-8", errors="ignore"))
            result["settings"] = {
                "optimizeAgentExperienceEnabled": st.get("optimizeAgentExperienceEnabled"),
                "repoSnapshotIndexingEnabled": st.get("repoSnapshotIndexingEnabled"),
                "modelIoFullRetentionEnabled": st.get("modelIoFullRetentionEnabled"),
                "locale": st.get("locale"),
                "path": str(SETTING),
            }
        except Exception as e:
            result["settings"] = {"error": str(e)}

    if not CHECKPOINTS.exists():
        result["workspaces"] = []
        result["global"] = {
            "switchesOffButActive": False,
            "machineBand": "E",
            "machineLabel": "拉",
            "machineScore": 0,
            "summary": "本机无 ~/.zcode/v2/checkpoints，未见快照泄漏产物。",
        }
        return result

    for state_path in sorted(CHECKPOINTS.glob("*/state.json")):
        wdir = state_path.parent
        try:
            state = json.loads(state_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception as e:
            state = {"_error": str(e)}
        cs = state.get("lastCompressedSize") or {}
        act = state.get("activeUpload") or state.get("pendingUpload") or {}
        attr = act.get("attribution") or {}
        enc_path = act.get("encryptedArtifactPath")
        pending_enc = bool(enc_path and Path(enc_path).exists())
        pending_size = Path(enc_path).stat().st_size if pending_enc else 0
        env_path = act.get("encryptionEnvelopePath")
        envelope = parse_envelope(Path(env_path)) if env_path and Path(env_path).exists() else {}

        # manifests — use largest/latest json
        mdir = wdir / "manifests"
        manifest = {}
        if mdir.exists():
            mfs = sorted(mdir.glob("*.json"), key=lambda p: p.stat().st_size, reverse=True)
            if mfs:
                manifest = parse_manifest_stats(mfs[0])

        extra = {}
        edir = wdir / "extra-manifests"
        if edir.exists():
            ems = sorted(edir.glob("*.json"), key=lambda p: p.stat().st_size, reverse=True)
            if ems:
                extra = parse_extra_manifest(ems[0])

        rec = {
            "key": wdir.name,
            "workspacePath": state.get("workspacePath") or state.get("workspaceKey") or "",
            "encryptedSizeBytes": cs.get("encryptedSizeBytes") or pending_size,
            "workspaceSizeBytes": cs.get("workspaceSizeBytes") or 0,
            "failureCount": state.get("failureCount") or 0,
            "kind": act.get("kind") or "",
            "captureStage": attr.get("captureStage") or "",
            "uploadCredentialHandle": act.get("uploadCredentialHandle") or "",
            "pendingEnc": pending_enc,
            "pendingEncPath": enc_path or "",
            "pendingEncBytes": pending_size,
            "checkpointDirBytes": dir_size(wdir),
            "envelope": envelope,
            "manifest": {
                "fileCount": manifest.get("fileCount"),
                "gitBytes": manifest.get("gitBytes"),
                "srcBytes": manifest.get("srcBytes"),
                "totalBytes": manifest.get("totalBytes"),
                "gitRatio": manifest.get("gitRatio") or 0,
                "topCats": manifest.get("topCats") or [],
                "path": manifest.get("path"),
            },
            "gitRatio": manifest.get("gitRatio") or 0,
            "extraHasGlobal": bool(extra.get("hasGlobalConfigs")),
            "extraGlobalConfigs": extra.get("globalConfigs") or [],
            "extraFiles": (extra.get("files") or [])[:20],
            "statePath": str(state_path),
        }
        result["workspaces"].append(rec)

    opt_off = result["settings"].get("optimizeAgentExperienceEnabled") is False
    idx_off = result["settings"].get("repoSnapshotIndexingEnabled") is False
    has_art = any(
        w.get("pendingEnc") or (w.get("checkpointDirBytes") or 0) > 1024 for w in result["workspaces"]
    )
    switches_off_but_active = bool(opt_off and idx_off and has_art)

    scored = []
    for rec in result["workspaces"]:
        sc = score_workspace(rec, switches_off_but_active)
        scored.append({**rec, **sc})
    # 夯 → 拉
    scored.sort(key=lambda x: (-x["score"], -(x.get("pendingEncBytes") or 0), x.get("workspacePath") or ""))
    result["workspaces"] = scored

    machine_score = 0
    if scored:
        machine_score = scored[0]["score"]
    if switches_off_but_active:
        machine_score = min(100, max(machine_score, 70))
    if result["sizes"]["checkpoints"] >= 100 * 1024 * 1024:
        machine_score = min(100, max(machine_score, 60))

    if machine_score >= 70:
        mband, mlabel = "S", "夯"
    elif machine_score >= 50:
        mband, mlabel = "A", "很夯"
    elif machine_score >= 35:
        mband, mlabel = "B", "有点夯"
    elif machine_score >= 20:
        mband, mlabel = "C", "一般"
    elif machine_score >= 1:
        mband, mlabel = "D", "偏拉"
    else:
        mband, mlabel = "E", "拉"

    result["global"] = {
        "switchesOffButActive": switches_off_but_active,
        "optimizeAgentExperienceEnabled": result["settings"].get("optimizeAgentExperienceEnabled"),
        "repoSnapshotIndexingEnabled": result["settings"].get("repoSnapshotIndexingEnabled"),
        "machineScore": machine_score,
        "machineBand": mband,
        "machineLabel": mlabel,
        "checkpointsHuman": human(result["sizes"]["checkpoints"]),
        "zcodeHuman": human(result["sizes"]["zcodeTotal"]),
        "pendingCount": sum(1 for w in result["workspaces"] if w.get("pendingEnc")),
        "pendingBytes": sum(w.get("pendingEncBytes") or 0 for w in result["workspaces"]),
        "summary": (
            "检测到登录态快照打包/待传产物，且相关 UI 开关未启用仍持续产出。"
            if switches_off_but_active
            else ("检测到 checkpoints/快照痕迹。" if result["workspaces"] else "未见快照泄漏产物。")
        ),
    }
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Collect ZCode leak audit evidence (read-only)")
    ap.add_argument("--json", default="/tmp/zcode-audit.json", help="output json path")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    data = collect()
    out = Path(args.json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    if not args.quiet:
        g = data.get("global") or {}
        print(f"wrote {out}")
        print(f"machine: {g.get('machineLabel')} score={g.get('machineScore')}")
        print(f"checkpoints: {g.get('checkpointsHuman')} pending={g.get('pendingCount')}")
        for w in data.get("workspaces") or []:
            print(
                f"  [{w.get('label')}] {w.get('score'):3d}  "
                f"{human(w.get('pendingEncBytes') or 0):>8}  git={float(w.get('gitRatio') or 0)*100:5.1f}%  "
                f"{w.get('workspacePath')}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
