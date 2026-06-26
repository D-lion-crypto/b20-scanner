#!/usr/bin/env python3
"""Local web UI for the B20 scanner."""

from __future__ import annotations

import json
import argparse
import base64
import secrets
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from eth_hash.auto import keccak

from b20_scanner import (
    B20Token,
    RpcClient,
    scan,
    token_rows,
    write_csv,
    write_html,
    write_json,
)


ROOT = Path(__file__).resolve().parent
DEFAULT_RPC = "https://mainnet.base.org"
ACTIVATION_REGISTRY = "0x8453000000000000000000000000000000000001"
CDP_SQL_ENDPOINT = "https://api.cdp.coinbase.com/platform/v2/data/query/run"
CDP_SQL_HOST = "api.cdp.coinbase.com"
CDP_SQL_PATH = "/platform/v2/data/query/run"
CDP_B20_SQL = """
SELECT
  block_number,
  block_timestamp,
  transaction_hash,
  log_index,
  parameters['token'] AS token_address,
  parameters['name'] AS name,
  parameters['symbol'] AS symbol,
  parameters['decimals'] AS decimals
FROM base.events
WHERE event_signature = 'B20Created(address,uint8,string,string,uint8,bytes)'
  AND address = '0xB20f000000000000000000000000000000000000'
  AND action = 'added'
ORDER BY block_number DESC, log_index DESC
LIMIT 100
"""

STATE_LOCK = threading.Lock()
STATE: dict[str, Any] = {
    "running": False,
    "monitoring": False,
    "stop_requested": False,
    "done": False,
    "error": "",
    "logs": [],
    "tokens": [],
    "token_objects": [],
    "seen": set(),
    "started_at": None,
    "finished_at": None,
    "last_scanned_block": None,
    "params": {},
}


INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>B20 代币扫描器</title>
  <style>
    :root { font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; color: #151515; background: #f6f7f8; }
    body { margin: 0; }
    main { max-width: 1440px; margin: 0 auto; padding: 24px; }
    h1 { margin: 0 0 8px; font-size: 26px; }
    p { color: #555; margin: 0 0 18px; }
    section { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 18px; margin-bottom: 16px; }
    label { display: grid; gap: 6px; font-size: 13px; font-weight: 650; }
    input, select, textarea { min-height: 36px; padding: 0 10px; border: 1px solid #b8bdc3; border-radius: 6px; font: inherit; background: #fff; }
    textarea { min-height: 110px; padding: 10px; resize: vertical; font-family: Consolas, ui-monospace, monospace; font-size: 12px; }
    .grid { display: grid; grid-template-columns: minmax(320px, 2fr) repeat(4, minmax(120px, 1fr)); gap: 12px; align-items: end; }
    .launchGrid { display: grid; grid-template-columns: minmax(260px, 1.2fr) minmax(160px, .7fr); gap: 12px; align-items: end; }
    .full { grid-column: 1 / -1; }
    .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 14px; }
    button, a.button { min-height: 36px; padding: 0 14px; border: 1px solid #1f2937; border-radius: 6px; background: #111827; color: #fff; text-decoration: none; cursor: pointer; display: inline-flex; align-items: center; font-weight: 650; }
    button.secondary, a.secondary { background: #fff; color: #111827; border-color: #b8bdc3; }
    button:disabled { opacity: .55; cursor: not-allowed; }
    #status { font-weight: 700; }
    #log { height: 160px; overflow: auto; background: #0f172a; color: #d1e7ff; padding: 12px; border-radius: 6px; font: 12px/1.5 Consolas, monospace; white-space: pre-wrap; }
    .tableWrap { overflow: auto; max-height: 65vh; border: 1px solid #ddd; border-radius: 8px; }
    table { width: 100%; border-collapse: collapse; background: #fff; font-size: 14px; }
    th, td { border-bottom: 1px solid #e5e7eb; padding: 10px; text-align: left; vertical-align: top; }
    th { position: sticky; top: 0; background: #f8fafc; z-index: 1; }
    code { font: 12px Consolas, monospace; word-break: break-all; }
    .actions { display: flex; gap: 6px; flex-wrap: wrap; min-width: 190px; }
    .actions button, .actions a { min-height: 30px; padding: 0 9px; font-size: 13px; border-radius: 6px; }
    .pill { display: inline-flex; align-items: center; min-height: 24px; padding: 0 8px; border-radius: 999px; background: #eef2ff; color: #3730a3; font-size: 12px; font-weight: 700; }
    .statusGrid { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
    .statusCard { border: 1px solid #d0d5dd; border-radius: 8px; padding: 10px 12px; min-width: 180px; }
    .statusCard strong { display: block; margin-bottom: 4px; }
    .ok { color: #067647; }
    .bad { color: #b42318; }
    .muted { color: #667085; }
    @media (max-width: 900px) { .grid, .launchGrid { grid-template-columns: 1fr; } .full { grid-column: auto; } main { padding: 14px; } }
  </style>
</head>
<body>
<main>
  <h1>B20 代币扫描器</h1>
  <p>填入 Base 主网 RPC 后点击扫描。扫描只读日志，不需要私钥；导入、买入、卖出都会交给浏览器钱包确认。</p>

  <section>
    <div class="grid">
      <label>Base 主网 RPC
        <input id="rpc" value="__DEFAULT_RPC__" />
      </label>
      <label>扫描模式
        <select id="mode" onchange="toggleMode()">
          <option value="monitor">持续扫描新区块</option>
          <option value="last">最近区块</option>
          <option value="range">指定区间</option>
        </select>
      </label>
      <label id="lastWrap">最近 N 个区块
        <input id="last" type="number" value="10000" min="1" step="1" />
      </label>
      <label class="rangeOnly" style="display:none">起始区块
        <input id="fromBlock" type="number" min="0" step="1" />
      </label>
      <label class="rangeOnly" style="display:none">结束区块
        <input id="toBlock" type="number" min="0" step="1" />
      </label>
      <label>分片大小
        <input id="chunkSize" type="number" value="5000" min="1" step="1" />
      </label>
      <label>CDP API Key ID（可选）
        <input id="cdpKeyId" placeholder="Secret API key ID" />
      </label>
      <label>CDP Secret（可选）
        <input id="cdpSecret" type="password" placeholder="Secret API key secret" />
      </label>
    </div>
    <div class="row">
      <label style="display:flex; grid-template-columns:auto 1fr; align-items:center; gap:8px; font-weight:500;">
        <input id="enrich" type="checkbox" checked style="min-height:0" />
        读取链上名称、供应量、暂停状态
      </label>
    </div>
    <div class="row">
      <button id="scanBtn" onclick="startScan()">开始扫描</button>
      <button id="stopBtn" class="secondary" onclick="stopScan()" disabled>停止监控</button>
      <button class="secondary" onclick="checkActivation()">刷新上线状态</button>
      <a class="button secondary" href="/b20_tokens.csv" target="_blank">下载 CSV</a>
      <a class="button secondary" href="/b20_tokens.json" target="_blank">下载 JSON</a>
      <a class="button secondary" href="/b20_tokens.html" target="_blank">打开静态面板</a>
      <span id="status" class="muted">等待扫描</span>
    </div>
    <div class="statusGrid">
      <div class="statusCard">
        <strong>B20 Asset</strong>
        <span id="assetStatus" class="muted">等待查询</span>
      </div>
      <div class="statusCard">
        <strong>B20 Stablecoin</strong>
        <span id="stableStatus" class="muted">等待查询</span>
      </div>
      <div class="statusCard">
        <strong>当前区块</strong>
        <span id="activationBlock" class="muted">-</span>
      </div>
    </div>
  </section>

  <section>
    <h2>上线后自动提交部署交易</h2>
    <div class="launchGrid">
      <label>launchB20 合约地址
        <input id="launchTo" placeholder="0x274D92df0d1CEfF9080360191feE0d3299c21B49" />
      </label>
      <label>交易 value（ETH）
        <input id="launchValueEth" value="0.01" inputmode="decimal" />
      </label>
      <label class="full">launchB20 calldata
        <textarea id="launchCalldata" placeholder="0x..."></textarea>
      </label>
    </div>
    <div class="row">
      <button class="secondary" onclick="connectWallet()">连接钱包</button>
      <button id="armLaunchBtn" onclick="enableAutoLaunch()">启用上线后自动提交</button>
      <button id="disarmLaunchBtn" class="secondary" onclick="disableAutoLaunch()" disabled>停止自动提交</button>
      <span id="walletStatus" class="muted">钱包未连接</span>
      <span id="launchStatus" class="muted">等待启用</span>
    </div>
  </section>

  <section>
    <div class="row" style="margin-top:0; justify-content:space-between;">
      <div><span class="pill" id="count">0 个代币</span></div>
      <input id="filter" placeholder="按名称、符号、合约地址或风险提示过滤" oninput="renderTable()" style="width:min(520px, 90vw)" />
    </div>
    <div id="log">等待扫描...</div>
  </section>

  <section>
    <div class="tableWrap">
      <table>
        <thead>
          <tr>
            <th>符号</th><th>名称</th><th>类型</th><th>合约地址</th><th>精度</th><th>总供应</th><th>风险提示</th><th>操作</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </section>
</main>
<script>
let tokens = [];
let pollTimer = null;
let walletAccount = '';
let autoLaunchEnabled = false;
let autoLaunchTriggered = false;

function toggleMode() {
  const mode = document.getElementById('mode').value;
  document.getElementById('lastWrap').style.display = mode === 'last' || mode === 'monitor' ? 'grid' : 'none';
  for (const el of document.querySelectorAll('.rangeOnly')) el.style.display = mode === 'range' ? 'grid' : 'none';
}

async function startScan() {
  const mode = document.getElementById('mode').value;
  const payload = {
    rpc: document.getElementById('rpc').value.trim(),
    mode,
    last: Number(document.getElementById('last').value || 10000),
    from_block: document.getElementById('fromBlock').value ? Number(document.getElementById('fromBlock').value) : null,
    to_block: document.getElementById('toBlock').value ? Number(document.getElementById('toBlock').value) : null,
    chunk_size: Number(document.getElementById('chunkSize').value || 5000),
    min_chunk_size: 10,
    interval: 3,
    enrich: document.getElementById('enrich').checked,
    cdp_key_id: document.getElementById('cdpKeyId').value.trim(),
    cdp_secret: document.getElementById('cdpSecret').value.trim()
  };
  document.getElementById('scanBtn').disabled = true;
  document.getElementById('stopBtn').disabled = mode !== 'monitor';
  document.getElementById('status').textContent = '扫描中...';
  document.getElementById('log').textContent = '正在提交扫描任务...';
  const res = await fetch('/api/scan', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  const data = await res.json();
  if (!res.ok) {
    document.getElementById('scanBtn').disabled = false;
    document.getElementById('status').textContent = '启动失败';
    document.getElementById('log').textContent = data.error || '启动失败';
    return;
  }
  pollTimer = setInterval(pollStatus, 1000);
  pollStatus();
}

async function stopScan() {
  await fetch('/api/stop', { method: 'POST' });
  document.getElementById('stopBtn').disabled = true;
  document.getElementById('status').textContent = '正在停止...';
}

async function checkActivation() {
  const rpc = encodeURIComponent(document.getElementById('rpc').value.trim());
  const res = await fetch(`/api/activation?rpc=${rpc}`);
  const data = await res.json();
  if (!res.ok) {
    document.getElementById('assetStatus').textContent = data.error || '查询失败';
    document.getElementById('assetStatus').className = 'bad';
    document.getElementById('stableStatus').textContent = '查询失败';
    document.getElementById('stableStatus').className = 'bad';
    return;
  }
  setActivationText('assetStatus', data.asset);
  setActivationText('stableStatus', data.stablecoin);
  document.getElementById('activationBlock').textContent = data.block_number || '-';
  await maybeAutoLaunch(data);
}

function setActivationText(id, active) {
  const el = document.getElementById(id);
  el.textContent = active ? '已上线，可部署' : '未上线，继续等待';
  el.className = active ? 'ok' : 'bad';
}

async function pollStatus() {
  const res = await fetch('/api/status');
  const data = await res.json();
  document.getElementById('status').textContent = data.monitoring ? `持续扫描中，已扫到区块 ${data.last_scanned_block || '-'}` : (data.running ? '扫描中...' : (data.error ? '扫描失败' : (data.done ? '扫描完成' : '等待扫描')));
  document.getElementById('log').textContent = (data.logs || []).join('\\n') || '等待扫描...';
  document.getElementById('log').scrollTop = document.getElementById('log').scrollHeight;
  await loadResults();
  if (!data.running) {
    clearInterval(pollTimer);
    document.getElementById('scanBtn').disabled = false;
    document.getElementById('stopBtn').disabled = true;
    await loadResults();
  }
}

async function loadResults() {
  const res = await fetch('/api/results');
  const data = await res.json();
  tokens = data.tokens || [];
  renderTable();
}

function renderTable() {
  const q = document.getElementById('filter').value.toLowerCase();
  const rows = tokens.filter(t => JSON.stringify(t).toLowerCase().includes(q));
  document.getElementById('count').textContent = `${rows.length} / ${tokens.length} 个代币`;
  document.getElementById('rows').innerHTML = rows.map(t => {
    const buy = t.buy_url;
    const sell = t.sell_url;
    const scan = t.basescan;
    return `<tr>
      <td>${escapeHtml(t.symbol)}</td>
      <td>${escapeHtml(t.name)}</td>
      <td>${escapeHtml(t.variant)}</td>
      <td><code>${escapeHtml(t.address)}</code></td>
      <td>${escapeHtml(t.decimals)}</td>
      <td><code>${escapeHtml(t.total_supply || '')}</code></td>
      <td>${escapeHtml((t.warnings || '') + (t.source ? ` 来源:${t.source}` : ''))}</td>
      <td class="actions">
        <button class="secondary" onclick="addToken('${t.address}', '${escapeAttr(t.symbol)}', ${Number(t.decimals) || 18})">导入</button>
        <a class="button" href="${buy}" target="_blank" rel="noreferrer">买入</a>
        <a class="button secondary" href="${sell}" target="_blank" rel="noreferrer">卖出</a>
        <a class="button secondary" href="${scan}" target="_blank" rel="noreferrer">查看</a>
      </td>
    </tr>`;
  }).join('');
}

async function addToken(address, symbol, decimals) {
  if (!window.ethereum) {
    alert('没有检测到浏览器钱包，请先安装或启用钱包插件。');
    return;
  }
  await ensureBaseChain();
  await window.ethereum.request({
    method: 'wallet_watchAsset',
    params: { type: 'ERC20', options: { address, symbol, decimals } }
  });
}

async function ensureBaseChain() {
  await window.ethereum.request({
    method: 'wallet_switchEthereumChain',
    params: [{ chainId: '0x2105' }],
  }).catch(async (err) => {
    if (err.code === 4902) {
      await window.ethereum.request({
        method: 'wallet_addEthereumChain',
        params: [{
          chainId: '0x2105',
          chainName: 'Base',
          nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
          rpcUrls: ['https://mainnet.base.org'],
          blockExplorerUrls: ['https://basescan.org']
        }],
      });
    } else {
      throw err;
    }
  });
}

async function connectWallet() {
  if (!window.ethereum) {
    alert('没有检测到浏览器钱包，请先安装或启用钱包插件。');
    return;
  }
  await ensureBaseChain();
  const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
  walletAccount = accounts && accounts[0] ? accounts[0] : '';
  document.getElementById('walletStatus').textContent = walletAccount ? `已连接 ${shortAddress(walletAccount)}` : '钱包未连接';
  document.getElementById('walletStatus').className = walletAccount ? 'ok' : 'bad';
}

async function enableAutoLaunch() {
  const to = document.getElementById('launchTo').value.trim();
  const data = document.getElementById('launchCalldata').value.trim();
  try {
    if (!isAddress(to)) throw new Error('launchB20 合约地址不正确');
    normalizeHexData(data);
    ethToWeiHex(document.getElementById('launchValueEth').value.trim() || '0');
    if (!walletAccount) await connectWallet();
    if (!walletAccount) throw new Error('钱包未连接');
    autoLaunchEnabled = true;
    autoLaunchTriggered = false;
    updateLaunchButtons();
    setLaunchStatus('已启用：检测到 B20 Asset 上线后会自动弹出钱包确认', 'ok');
  } catch (err) {
    setLaunchStatus(err.message || String(err), 'bad');
  }
}

function disableAutoLaunch() {
  autoLaunchEnabled = false;
  autoLaunchTriggered = false;
  updateLaunchButtons();
  setLaunchStatus('已停止自动提交', 'muted');
}

async function maybeAutoLaunch(data) {
  if (!autoLaunchEnabled || autoLaunchTriggered || !data.asset) return;
  autoLaunchTriggered = true;
  autoLaunchEnabled = false;
  updateLaunchButtons();
  setLaunchStatus('B20 Asset 已上线，正在请求钱包确认...', 'ok');
  try {
    if (!window.ethereum) throw new Error('没有检测到浏览器钱包');
    await ensureBaseChain();
    if (!walletAccount) {
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
      walletAccount = accounts && accounts[0] ? accounts[0] : '';
    }
    const tx = {
      from: walletAccount,
      to: document.getElementById('launchTo').value.trim(),
      data: normalizeHexData(document.getElementById('launchCalldata').value.trim()),
      value: ethToWeiHex(document.getElementById('launchValueEth').value.trim() || '0')
    };
    const hash = await window.ethereum.request({ method: 'eth_sendTransaction', params: [tx] });
    setLaunchStatus(`已提交交易：${hash}`, 'ok');
  } catch (err) {
    autoLaunchEnabled = false;
    autoLaunchTriggered = false;
    updateLaunchButtons();
    setLaunchStatus(`提交失败，已停止自动提交：${err.message || err}`, 'bad');
  }
}

function updateLaunchButtons() {
  document.getElementById('armLaunchBtn').disabled = autoLaunchEnabled || autoLaunchTriggered;
  document.getElementById('disarmLaunchBtn').disabled = !autoLaunchEnabled;
}

function setLaunchStatus(text, className) {
  const el = document.getElementById('launchStatus');
  el.textContent = text;
  el.className = className || 'muted';
}

function isAddress(value) {
  return /^0x[a-fA-F0-9]{40}$/.test(value);
}

function normalizeHexData(value) {
  const compact = String(value || '').replace(/\\s+/g, '');
  if (!/^0x[a-fA-F0-9]*$/.test(compact) || compact.length < 10 || compact.length % 2 !== 0) {
    throw new Error('calldata 必须是 0x 开头的十六进制数据');
  }
  return compact;
}

function ethToWeiHex(value) {
  const text = String(value || '0').trim();
  if (!/^\\d+(\\.\\d{0,18})?$/.test(text)) throw new Error('value ETH 格式不正确');
  const [whole, fraction = ''] = text.split('.');
  const wei = BigInt(whole || '0') * 10n ** 18n + BigInt((fraction + '0'.repeat(18)).slice(0, 18));
  return '0x' + wei.toString(16);
}

function shortAddress(address) {
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function escapeAttr(value) {
  return String(value ?? '').replace(/['\\\\]/g, '\\\\$&');
}

loadResults();
checkActivation();
setInterval(checkActivation, 3000);
</script>
</body>
</html>
""".replace("__DEFAULT_RPC__", DEFAULT_RPC)


def set_state(**updates: Any) -> None:
    with STATE_LOCK:
        STATE.update(updates)


def append_log(message: str) -> None:
    with STATE_LOCK:
        logs = STATE.setdefault("logs", [])
        logs.append(message)
        del logs[:-300]


def snapshot() -> dict[str, Any]:
    with STATE_LOCK:
        params = dict(STATE["params"])
        for key in ("cdp_token", "cdp_key_id", "cdp_secret"):
            if params.get(key):
                params[key] = "***"
        return {
            "running": STATE["running"],
            "done": STATE["done"],
            "error": STATE["error"],
            "logs": list(STATE["logs"]),
            "started_at": STATE["started_at"],
            "finished_at": STATE["finished_at"],
            "monitoring": STATE["monitoring"],
            "last_scanned_block": STATE["last_scanned_block"],
            "params": params,
        }


def activation_status(rpc_url: str) -> dict[str, Any]:
    rpc = RpcClient(rpc_url)
    selector = keccak(b"isActivated(bytes32)")[:4].hex()

    def is_active(feature: bytes) -> bool:
        data = "0x" + selector + keccak(feature).hex()
        result = rpc.eth_call(ACTIVATION_REGISTRY, data)
        return bool(result and result != "0x" and int(result, 16) != 0)

    return {
        "asset": is_active(b"base.b20_asset"),
        "stablecoin": is_active(b"base.b20_stablecoin"),
        "block_number": rpc.block_number(),
    }


def cdp_request(token: str, sql: str) -> dict[str, Any]:
    body = json.dumps({"sql": sql}).encode("utf-8")
    req = urllib.request.Request(
        CDP_SQL_ENDPOINT,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "b20-scanner/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as res:
        return json.load(res)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def jwt_signing_input(header: dict[str, Any], payload: dict[str, Any]) -> bytes:
    return f"{b64url(json.dumps(header, separators=(',', ':')).encode())}.{b64url(json.dumps(payload, separators=(',', ':')).encode())}".encode()


def load_cdp_secret(secret: str) -> tuple[str, Any]:
    stripped = secret.strip()
    if "BEGIN" in stripped:
        key = serialization.load_pem_private_key(stripped.encode(), password=None)
        return "ES256", key
    raw = base64.b64decode(stripped)
    if len(raw) == 64:
        raw = raw[:32]
    if len(raw) != 32:
        raise ValueError("CDP Secret 不是有效的 Ed25519 base64 secret，也不是 PEM 私钥")
    return "EdDSA", ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def generate_cdp_jwt(key_id: str, secret: str) -> str:
    alg, private_key = load_cdp_secret(secret)
    now = int(time.time())
    header = {
        "alg": alg,
        "kid": key_id,
        "nonce": secrets.token_hex(16),
        "typ": "JWT",
    }
    payload = {
        "iss": "cdp",
        "sub": key_id,
        "nbf": now,
        "exp": now + 120,
        "uris": [f"POST {CDP_SQL_HOST}{CDP_SQL_PATH}"],
    }
    signing_input = jwt_signing_input(header, payload)
    if alg == "EdDSA":
        signature = private_key.sign(signing_input)
    else:
        der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input.decode() + "." + b64url(signature)


def cdp_token_from_params(params: dict[str, Any]) -> str:
    token = str(params.get("cdp_token") or "").strip()
    if token:
        return token
    key_id = str(params.get("cdp_key_id") or "").strip()
    secret = str(params.get("cdp_secret") or "").strip()
    if key_id and secret:
        return generate_cdp_jwt(key_id, secret)
    return ""


def extract_cdp_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("rows", "data", "result", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
        if isinstance(value, dict):
            nested = extract_cdp_rows(value)
            if nested:
                return nested
    return []


def cdp_latest_b20_tokens(token: str) -> list[B20Token]:
    payload = cdp_request(token, CDP_B20_SQL)
    rows = extract_cdp_rows(payload)
    tokens: list[B20Token] = []
    for index, row in enumerate(rows):
        address = row.get("token_address") or row.get("token") or row.get("address")
        if not address:
            continue
        try:
            decimals = int(row.get("decimals") or 18)
        except (TypeError, ValueError):
            decimals = 18
        try:
            block_number = int(row.get("block_number") or 0)
        except (TypeError, ValueError):
            block_number = 0
        try:
            log_index = int(row.get("log_index") or index)
        except (TypeError, ValueError):
            log_index = index
        tokens.append(
            B20Token(
                block_number=block_number,
                tx_hash=str(row.get("transaction_hash") or ""),
                log_index=log_index,
                address=str(address),
                variant="B20",
                name=str(row.get("name") or ""),
                symbol=str(row.get("symbol") or ""),
                decimals=decimals,
                warnings="",
                source="cdp",
            )
        )
    return tokens


def persist_token_objects(tokens: list[Any]) -> None:
    tokens.sort(key=lambda item: (item.block_number, item.log_index), reverse=True)
    write_csv(ROOT / "b20_tokens.csv", tokens)
    write_json(ROOT / "b20_tokens.json", tokens)
    write_html(ROOT / "b20_tokens.html", tokens)
    rows = token_rows(tokens)
    with STATE_LOCK:
        STATE["token_objects"] = list(tokens)
        STATE["tokens"] = rows
        STATE["seen"] = {row["address"].lower() for row in rows}


def merge_tokens(new_tokens: list[Any]) -> int:
    with STATE_LOCK:
        existing = list(STATE.get("token_objects") or [])
        seen = set(STATE.get("seen") or set())
    added = 0
    for token in new_tokens:
        key = token.address.lower()
        if key in seen:
            continue
        existing.append(token)
        seen.add(key)
        added += 1
    if added:
        persist_token_objects(existing)
    return added


def run_once(params: dict[str, Any]) -> None:
    try:
        set_state(
            running=True,
            monitoring=False,
            stop_requested=False,
            done=False,
            error="",
            logs=[],
            tokens=[],
            token_objects=[],
            seen=set(),
            started_at=time.time(),
            finished_at=None,
            last_scanned_block=None,
            params=params,
        )
        append_log("开始连接 RPC...")
        rpc = RpcClient(params["rpc"])
        latest = int(params.get("to_block") or rpc.block_number())
        if params.get("mode") == "range":
            from_block = int(params["from_block"])
        else:
            last = int(params.get("last") or 10_000)
            from_block = max(0, latest - last + 1)
        if from_block > latest:
            raise ValueError(f"起始区块 {from_block} 大于结束区块 {latest}")
        append_log(f"扫描区间：{from_block} - {latest}")
        tokens = scan(
            rpc,
            from_block,
            latest,
            int(params.get("chunk_size") or 5000),
            enrich=bool(params.get("enrich", True)),
            min_chunk_size=int(params.get("min_chunk_size") or 10),
            progress=append_log,
        )
        persist_token_objects(tokens)
        set_state(running=False, monitoring=False, done=True, finished_at=time.time(), last_scanned_block=latest)
        append_log(f"扫描完成：发现 {len(tokens)} 个 B20 代币")
    except Exception as exc:
        set_state(running=False, monitoring=False, done=False, error=str(exc), finished_at=time.time())
        append_log(f"扫描失败：{exc}")


def run_monitor(params: dict[str, Any]) -> None:
    try:
        set_state(
            running=True,
            monitoring=True,
            stop_requested=False,
            done=False,
            error="",
            logs=[],
            tokens=[],
            token_objects=[],
            seen=set(),
            started_at=time.time(),
            finished_at=None,
            last_scanned_block=None,
            params=params,
        )
        append_log("开始连接 RPC...")
        rpc = RpcClient(params["rpc"])
        latest = rpc.block_number()
        backfill = int(params.get("last") or 1000)
        current = max(0, latest - backfill + 1)
        cdp_enabled = bool(str(params.get("cdp_token") or params.get("cdp_key_id") or "").strip())
        last_cdp_check = 0.0
        append_log(f"持续扫描已启动，先回扫最近 {backfill} 个区块，然后监听新区块")
        if cdp_enabled:
            append_log("CDP SQL 补漏已启用：会定期查询 Coinbase 索引结果")
        else:
            append_log("CDP SQL 补漏未启用：如需双保险，请填写 CDP API Key ID 和 Secret")

        while True:
            with STATE_LOCK:
                if STATE.get("stop_requested"):
                    break
            latest = rpc.block_number()
            if current <= latest:
                append_log(f"扫描新区间：{current} - {latest}")
                tokens = scan(
                    rpc,
                    current,
                    latest,
                    int(params.get("chunk_size") or 5000),
                    enrich=bool(params.get("enrich", True)),
                    min_chunk_size=int(params.get("min_chunk_size") or 10),
                    progress=append_log,
                )
                added = merge_tokens(tokens)
                if added:
                    append_log(f"发现 {added} 个新 B20 代币，已追加到表格")
                else:
                    append_log("本轮没有发现新的 B20 代币")
                set_state(last_scanned_block=latest)
                current = latest + 1

            if cdp_enabled and time.time() - last_cdp_check >= 20:
                try:
                    cdp_token = cdp_token_from_params(params)
                    cdp_tokens = cdp_latest_b20_tokens(cdp_token)
                    added = merge_tokens(cdp_tokens)
                    append_log(f"CDP SQL 补漏完成：返回 {len(cdp_tokens)} 条，新增 {added} 条")
                    last_cdp_check = time.time()
                except Exception as exc:
                    append_log(f"CDP SQL 补漏失败：{str(exc)[:180]}")
                    last_cdp_check = time.time()
            time.sleep(float(params.get("interval") or 3))

        set_state(running=False, monitoring=False, done=True, stop_requested=False, finished_at=time.time())
        append_log("持续扫描已停止")
    except Exception as exc:
        set_state(running=False, monitoring=False, done=False, stop_requested=False, error=str(exc), finished_at=time.time())
        append_log(f"持续扫描失败：{exc}")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_text(INDEX_HTML, "text/html; charset=utf-8")
        elif parsed.path == "/api/status":
            self.send_json(snapshot())
        elif parsed.path == "/api/activation":
            query = parse_qs(parsed.query)
            rpc_url = (query.get("rpc") or [DEFAULT_RPC])[0]
            try:
                self.send_json(activation_status(rpc_url))
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=500)
        elif parsed.path == "/api/results":
            with STATE_LOCK:
                tokens = list(STATE.get("tokens") or [])
                can_load_previous = not STATE.get("started_at")
            if not tokens and can_load_previous and (ROOT / "b20_tokens.json").exists():
                try:
                    tokens = json.loads((ROOT / "b20_tokens.json").read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    tokens = []
            self.send_json({"tokens": tokens})
        elif parsed.path in {"/b20_tokens.csv", "/b20_tokens.json", "/b20_tokens.html"}:
            self.send_file(ROOT / parsed.path.lstrip("/"))
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/stop":
            set_state(stop_requested=True)
            self.send_json({"ok": True})
            return
        if path != "/api/scan":
            self.send_error(404)
            return
        with STATE_LOCK:
            if STATE["running"]:
                self.send_json({"error": "已有扫描任务正在运行"}, status=409)
                return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            params = json.loads(self.rfile.read(length).decode("utf-8"))
            if not params.get("rpc"):
                raise ValueError("RPC 不能为空")
            if params.get("mode") == "range" and params.get("from_block") is None:
                raise ValueError("指定区间模式需要填写起始区块")
        except Exception as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        target = run_monitor if params.get("mode") == "monitor" else run_once
        thread = threading.Thread(target=target, args=(params,), daemon=True)
        thread.start()
        self.send_json({"ok": True})

    def send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text: str, content_type: str) -> None:
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path: Path) -> None:
        if not path.exists():
            self.send_error(404)
            return
        types = {
            ".csv": "text/csv; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".html": "text/html; charset=utf-8",
        }
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", types.get(path.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="B20 local web scanner")
    parser.add_argument("--port", type=int, default=8788, help="Local web server port")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"B20 web scanner running at http://127.0.0.1:{args.port}/")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
