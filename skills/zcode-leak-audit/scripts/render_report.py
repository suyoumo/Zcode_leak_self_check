#!/usr/bin/env python3
"""Render ZCode leak audit JSON into a mobile HTML report ranked 夯→拉."""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path


def human(n) -> str:
    try:
        f = float(n or 0)
    except Exception:
        return "—"
    for u in ("B", "KB", "MB", "GB"):
        if f < 1024 or u == "GB":
            return f"{f:.1f}{u}" if u != "B" else f"{int(f)}B"
        f /= 1024
    return f"{f:.1f}GB"


def esc(s) -> str:
    return html.escape("" if s is None else str(s))


BAND_COLOR = {
    "S": "#E2554D",
    "A": "#F07A5A",
    "B": "#E8A23A",
    "C": "#4EC4D6",
    "D": "#8B9AAB",
    "E": "#3CB88A",
}


def band_badge(band: str, label: str) -> str:
    color = BAND_COLOR.get(band, "#8B9AAB")
    return (
        f'<span class="band" style="background:{color}22;color:{color};border-color:{color}55">'
        f"{esc(label)}</span>"
    )


def render(data: dict) -> str:
    g = data.get("global") or {}
    settings = data.get("settings") or {}
    sizes = data.get("sizes") or {}
    app = data.get("app") or {}
    workspaces = data.get("workspaces") or []
    defense = data.get("defense") or {}

    mlabel = g.get("machineLabel") or "拉"
    mscore = g.get("machineScore") or 0
    mband = g.get("machineBand") or "E"

    rows = []
    for w in workspaces:
        git_pct = float(w.get("gitRatio") or 0) * 100
        env = w.get("envelope") or {}
        rows.append(
            f"""
      <div class="card ws">
        <div class="ws-head">
          <div class="ws-title">{esc(w.get('workspacePath') or w.get('key'))}</div>
          {band_badge(w.get('band') or 'E', w.get('label') or '拉')}
        </div>
        <div class="ws-score"><b>{esc(w.get('score'))}</b><span>泄漏分</span></div>
        <div class="metrics">
          <div><i>pending</i><b>{human(w.get('pendingEncBytes') or 0)}</b></div>
          <div><i>密文记录</i><b>{human(w.get('encryptedSizeBytes'))}</b></div>
          <div><i>.git 占比</i><b>{git_pct:.1f}%</b></div>
          <div><i>失败重试</i><b>{esc(w.get('failureCount'))}</b></div>
          <div><i>触发</i><b>{esc(w.get('captureStage') or '—')}</b></div>
          <div><i>类型</i><b>{esc(w.get('kind') or '—')}</b></div>
        </div>
        <ul class="reasons">
          {''.join(f'<li>{esc(r)}</li>' for r in (w.get('reasons') or []))}
        </ul>
        <div class="mono">
          keyWrap={esc(env.get('keyWrapAlgorithm') or '—')} · content={esc(env.get('contentAlgorithm') or '—')}<br>
          handle={esc(w.get('uploadCredentialHandle') or '—')}<br>
          path={esc(w.get('pendingEncPath') or '—')}
        </div>
      </div>"""
        )

    extra_global = []
    for w in workspaces:
        for item in w.get("extraGlobalConfigs") or []:
            extra_global.append(
                f"<li><code>{esc(item.get('path'))}</code> · {esc(item.get('source'))} · {human(item.get('sizeBytes'))}</li>"
            )

    mac_lines = defense.get("macos") or []
    lin_lines = defense.get("linux") or []

    schema_hits = app.get("schemaHits") or []
    endpoints = app.get("endpointHits") or []

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<title>ZCode 泄漏审计报告 · 夯→拉</title>
<style>
:root{{
  --bg:#0B0F14; --panel:#121820; --panel2:#18202A; --ink:#E8EEF4; --muted:#8B9AAB;
  --line:#243041; --risk:#E2554D; --warn:#E8A23A; --ok:#3CB88A; --cyan:#4EC4D6;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:var(--sans);background:radial-gradient(1000px 500px at 50% -10%,#162033,#0B0F14 55%);color:var(--ink);line-height:1.55;padding:16px 14px 40px}}
.wrap{{max-width:430px;margin:0 auto}}
h1{{font-size:22px;line-height:1.25;margin:8px 0}}
.lede{{color:var(--muted);font-size:13.5px}}
.verdict{{margin-top:12px;border-radius:16px;padding:14px;border:1px solid rgba(226,85,77,.4);background:linear-gradient(145deg,rgba(226,85,77,.16),rgba(226,85,77,.04))}}
.verdict .label{{font-size:11px;letter-spacing:.08em;color:#FF8D86}}
.verdict .main{{font-size:18px;font-weight:700;margin:4px 0 8px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.stats{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}}
.stat{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:12px}}
.stat .n{{font-family:var(--mono);font-size:20px;font-weight:700}}
.stat .l{{font-size:12px;color:var(--muted)}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:14px;margin-top:12px}}
.card h2{{font-size:15px;margin-bottom:8px}}
.rank-note{{font-size:12px;color:var(--muted);margin-top:10px}}
.ws-head{{display:flex;justify-content:space-between;gap:8px;align-items:flex-start}}
.ws-title{{font-size:13px;font-weight:600;word-break:break-all;flex:1}}
.band{{font-size:11px;font-weight:700;padding:3px 8px;border-radius:999px;border:1px solid;white-space:nowrap}}
.ws-score{{margin-top:8px;display:flex;align-items:baseline;gap:6px}}
.ws-score b{{font-family:var(--mono);font-size:28px}}
.ws-score span{{color:var(--muted);font-size:12px}}
.metrics{{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:8px}}
.metrics div{{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:8px}}
.metrics i{{display:block;font-style:normal;font-size:10px;color:var(--muted)}}
.metrics b{{font-family:var(--mono);font-size:12px}}
.reasons{{margin:10px 0 0 16px;font-size:12.5px;color:#C9D4E0}}
.reasons li{{margin:4px 0}}
.mono{{margin-top:8px;font-family:var(--mono);font-size:10.5px;color:#7E90A3;word-break:break-all;line-height:1.45}}
pre.cmd{{margin-top:8px;background:#0A0E13;border:1px solid var(--line);border-radius:12px;padding:12px;font-family:var(--mono);font-size:11.5px;color:#B8C7D6;overflow-x:auto;white-space:pre-wrap}}
.sw-row{{display:flex;justify-content:space-between;gap:8px;padding:8px 0;border-bottom:1px solid var(--line);font-size:13px}}
.sw-row:last-child{{border-bottom:0}}
.sw{{font-family:var(--mono);font-size:11px;padding:3px 8px;border-radius:999px}}
.sw.off{{background:rgba(226,85,77,.12);color:#FF8D86}}
.sw.on{{background:rgba(60,184,138,.12);color:#6FD9B0}}
.sw.na{{background:rgba(139,154,171,.12);color:var(--muted)}}
table.rk{{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px}}
table.rk th,table.rk td{{text-align:left;padding:7px 4px;border-bottom:1px solid var(--line);vertical-align:top}}
table.rk th{{color:var(--muted);font-weight:500;font-size:11px}}
.footer{{margin-top:18px;text-align:center;color:#5E6D7D;font-size:11px}}
ul.plain{{margin-left:16px;font-size:13px;color:#C9D4E0}}
ul.plain li{{margin:4px 0}}
code{{font-family:var(--mono);font-size:11.5px;color:#9FD7E8;background:rgba(78,196,214,.08);padding:1px 5px;border-radius:5px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="lede">zcode-leak-audit · 只读取证 · {esc(data.get('generatedAt'))}</div>
  <h1>ZCode 泄漏信息总结报告</h1>
  <p class="lede">按工作区泄漏程度从 <b style="color:#E2554D">夯</b>（最重）到 <b style="color:#3CB88A">拉</b>（最轻）排名。</p>

  <div class="verdict">
    <div class="label">MACHINE VERDICT</div>
    <div class="main">{band_badge(mlabel, mlabel)} <span>整机分 {esc(mscore)}</span></div>
    <p style="font-size:13px;color:#D6DEE8">{esc(g.get('summary'))}</p>
  </div>

  <div class="stats">
    <div class="stat"><div class="n" style="color:#E2554D">{esc(g.get('checkpointsHuman') or human(sizes.get('checkpoints')))}</div><div class="l">checkpoints</div></div>
    <div class="stat"><div class="n" style="color:#E8A23A">{esc(g.get('zcodeHuman') or human(sizes.get('zcodeTotal')))}</div><div class="l">~/.zcode 总占用</div></div>
    <div class="stat"><div class="n" style="color:#4EC4D6">{esc(g.get('pendingCount'))}</div><div class="l">pending 加密包</div></div>
    <div class="stat"><div class="n">{human(g.get('pendingBytes'))}</div><div class="l">pending 合计</div></div>
  </div>

  <div class="card">
    <h2>排名总表（夯 → 拉）</h2>
    <table class="rk">
      <tr><th>档</th><th>分</th><th>工作区</th><th>pending</th><th>.git</th></tr>
      {''.join(
        f"<tr><td>{band_badge(w.get('band'), w.get('label'))}</td><td>{esc(w.get('score'))}</td>"
        f"<td style='word-break:break-all'>{esc((w.get('workspacePath') or '')[-48:])}</td>"
        f"<td>{human(w.get('pendingEncBytes') or 0)}</td>"
        f"<td>{float(w.get('gitRatio') or 0)*100:.0f}%</td></tr>"
        for w in workspaces
      ) or '<tr><td colspan="5">无工作区快照记录</td></tr>'}
    </table>
    <div class="rank-note">档位：夯 ≥70 · 很夯 50–69 · 有点夯 35–49 · 一般 20–34 · 偏拉 1–19 · 拉 0</div>
  </div>

  <div class="card">
    <h2>UI 开关状态</h2>
    <div class="sw-row"><span>optimizeAgentExperienceEnabled</span>
      <span class="sw {'off' if settings.get('optimizeAgentExperienceEnabled') is False else ('on' if settings.get('optimizeAgentExperienceEnabled') is True else 'na')}">
        {esc(settings.get('optimizeAgentExperienceEnabled'))}
      </span></div>
    <div class="sw-row"><span>repoSnapshotIndexingEnabled</span>
      <span class="sw {'off' if settings.get('repoSnapshotIndexingEnabled') is False else ('on' if settings.get('repoSnapshotIndexingEnabled') is True else 'na')}">
        {esc(settings.get('repoSnapshotIndexingEnabled'))}
      </span></div>
    <div class="sw-row"><span>开关失效仍产出</span>
      <span class="sw {'off' if g.get('switchesOffButActive') else 'on'}">{esc('YES' if g.get('switchesOffButActive') else 'NO')}</span></div>
  </div>

  <div class="card">
    <h2>工作区详情（夯→拉）</h2>
    {''.join(rows) or '<p class="lede">无</p>'}
  </div>

  <div class="card">
    <h2>全局配置外带（extra-manifest）</h2>
    <ul class="plain">{''.join(extra_global) or '<li>未发现 global-configs 外带记录</li>'}</ul>
  </div>

  <div class="card">
    <h2>客户端信号</h2>
    <ul class="plain">
      <li>App 安装：{esc(app.get('appInstalled'))}</li>
      <li>端点：{esc(', '.join(endpoints) or '—')}</li>
      <li>repo_snapshot schema：{esc(', '.join(schema_hits[:8]) or '—')}</li>
    </ul>
  </div>

  <div class="card">
    <h2>防御（锁 checkpoints）</h2>
    <pre class="cmd"># macOS
{esc(chr(10).join(mac_lines))}

# 解除
{esc(defense.get('unlockMacos') or '')}

# Linux
{esc(chr(10).join(lin_lines))}
{esc(defense.get('unlockLinux') or '')}</pre>
  </div>

  <div class="card">
    <h2>边界说明</h2>
    <ul class="plain">
      <li>报告基于本机只读取证：打包、加密信封、.git 入包、开关状态可直接核实。</li>
      <li>「成功上传到 OSS」若无抓包/服务端回执，只记为间接证据（凭证句柄 + 重试）。</li>
      <li>报告不包含任何 API Key 明文。</li>
    </ul>
  </div>

  <div class="footer">skill: zcode-leak-audit · 排名方向 夯→拉 · 本地生成</div>
</div>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="/tmp/zcode-audit.json")
    ap.add_argument("--output", default="index.html")
    args = ap.parse_args()
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    # ensure ranked order even if upstream forgot
    ws = data.get("workspaces") or []
    band_order = {"S": 0, "A": 1, "B": 2, "C": 3, "D": 4, "E": 5}
    ws.sort(key=lambda w: (band_order.get(w.get("band"), 9), -(w.get("score") or 0), -(w.get("pendingEncBytes") or 0)))
    data["workspaces"] = ws
    html_text = render(data)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_text, encoding="utf-8")
    print(f"wrote {out.resolve()} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
