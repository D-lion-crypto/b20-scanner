#!/usr/bin/env python3
"""
Scan Base B20 tokens from the B20Factory precompile and export wallet-friendly
links. This script is read-only: it never asks for or uses a private key.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from eth_hash.auto import keccak


B20_FACTORY = "0xB20f000000000000000000000000000000000000"
BASE_CHAIN_ID = 8453
BASESCAN_TX = "https://basescan.org/tx/"
BASESCAN_TOKEN = "https://basescan.org/token/"
UNISWAP_BASE = "https://app.uniswap.org/swap?chain=base"
WETH_BASE = "0x4200000000000000000000000000000000000006"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

EVENT_SIGNATURE = "B20Created(address,uint8,string,string,uint8,bytes)"
EVENT_TOPIC = "0x" + keccak(EVENT_SIGNATURE.encode()).hex()

CALLS = {
    "name": "name()",
    "symbol": "symbol()",
    "decimals": "decimals()",
    "totalSupply": "totalSupply()",
    "supplyCap": "supplyCap()",
    "pausedFeatures": "pausedFeatures()",
}


@dataclass
class B20Token:
    block_number: int
    tx_hash: str
    log_index: int
    address: str
    variant: str
    name: str
    symbol: str
    decimals: int
    total_supply: str | None = None
    supply_cap: str | None = None
    paused_features: str | None = None
    warnings: str = ""
    source: str = "rpc"


class RpcClient:
    def __init__(self, rpc_url: str, timeout: int = 20, retries: int = 3):
        self.rpc_url = rpc_url
        self.timeout = timeout
        self.retries = retries
        self._next_id = 1

    def request(self, method: str, params: list[Any]) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": method,
            "params": params,
        }
        self._next_id += 1
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "b20-scanner/1.0"}

        for attempt in range(self.retries):
            req = urllib.request.Request(self.rpc_url, data=body, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as res:
                    data = json.load(res)
                if "error" in data:
                    raise RuntimeError(data["error"])
                return data["result"]
            except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
                if attempt + 1 == self.retries:
                    raise RuntimeError(f"RPC {method} failed: {exc}") from exc
                time.sleep(0.5 * (attempt + 1))
        raise RuntimeError(f"RPC {method} failed")

    def block_number(self) -> int:
        return int(self.request("eth_blockNumber", []), 16)

    def get_logs(self, from_block: int, to_block: int) -> list[dict[str, Any]]:
        return self.request(
            "eth_getLogs",
            [
                {
                    "fromBlock": hex(from_block),
                    "toBlock": hex(to_block),
                    "address": B20_FACTORY,
                    "topics": [EVENT_TOPIC],
                }
            ],
        )

    def eth_call(self, to: str, data: str) -> str:
        return self.request("eth_call", [{"to": to, "data": data}, "latest"])


def selector(signature: str) -> str:
    return keccak(signature.encode())[:4].hex()


def topic_to_address(topic: str) -> str:
    clean = topic.removeprefix("0x")
    return "0x" + clean[-40:]


def topic_to_int(topic: str) -> int:
    return int(topic, 16)


def read_word(data: bytes, index: int) -> int:
    start = index * 32
    return int.from_bytes(data[start : start + 32], "big")


def decode_string(data: bytes, offset: int) -> str:
    length = int.from_bytes(data[offset : offset + 32], "big")
    raw = data[offset + 32 : offset + 32 + length]
    return raw.decode("utf-8", errors="replace")


def decode_bytes(data: bytes, offset: int) -> bytes:
    length = int.from_bytes(data[offset : offset + 32], "big")
    return data[offset + 32 : offset + 32 + length]


def decode_b20_created(log: dict[str, Any]) -> B20Token:
    topics = log["topics"]
    data = bytes.fromhex(log["data"].removeprefix("0x"))
    name_offset = read_word(data, 0)
    symbol_offset = read_word(data, 1)
    decimals = read_word(data, 2)
    params_offset = read_word(data, 3)
    variant_id = topic_to_int(topics[2])

    # Force parse variantEventParams so malformed ABI data does not pass silently.
    _ = decode_bytes(data, params_offset)

    return B20Token(
        block_number=int(log["blockNumber"], 16),
        tx_hash=log["transactionHash"],
        log_index=int(log["logIndex"], 16),
        address=checksum_or_lower(topic_to_address(topics[1])),
        variant={0: "ASSET", 1: "STABLECOIN"}.get(variant_id, f"UNKNOWN_{variant_id}"),
        name=decode_string(data, name_offset),
        symbol=decode_string(data, symbol_offset),
        decimals=decimals,
    )


def checksum_or_lower(address: str) -> str:
    lower = address.lower().removeprefix("0x")
    if len(lower) != 40:
        return address
    hashed = keccak(lower.encode()).hex()
    out = ""
    for char, nibble in zip(lower, hashed):
        out += char.upper() if int(nibble, 16) >= 8 else char
    return "0x" + out


def decode_uint(result: str) -> int | None:
    if not result or result == "0x":
        return None
    return int(result, 16)


def decode_call_string(result: str) -> str | None:
    if not result or result == "0x":
        return None
    data = bytes.fromhex(result.removeprefix("0x"))
    try:
        return decode_string(data, read_word(data, 0))
    except Exception:
        return None


def decode_uint8_array(result: str) -> list[int] | None:
    if not result or result == "0x":
        return None
    data = bytes.fromhex(result.removeprefix("0x"))
    try:
        offset = read_word(data, 0)
        length = int.from_bytes(data[offset : offset + 32], "big")
        values = []
        pos = offset + 32
        for _ in range(length):
            values.append(int.from_bytes(data[pos : pos + 32], "big"))
            pos += 32
        return values
    except Exception:
        return None


def enrich_token(rpc: RpcClient, token: B20Token) -> B20Token:
    warnings: list[str] = []

    if not token.address.lower().startswith("0xb200"):
        warnings.append("address_not_b20_prefix")

    try:
        name = decode_call_string(rpc.eth_call(token.address, "0x" + selector(CALLS["name"])))
        symbol = decode_call_string(rpc.eth_call(token.address, "0x" + selector(CALLS["symbol"])))
        decimals = decode_uint(rpc.eth_call(token.address, "0x" + selector(CALLS["decimals"])))
        total_supply = decode_uint(rpc.eth_call(token.address, "0x" + selector(CALLS["totalSupply"])))
        supply_cap = decode_uint(rpc.eth_call(token.address, "0x" + selector(CALLS["supplyCap"])))
        paused = decode_uint8_array(rpc.eth_call(token.address, "0x" + selector(CALLS["pausedFeatures"])))

        if name and name != token.name:
            warnings.append("name_changed")
            token.name = name
        if symbol and symbol != token.symbol:
            warnings.append("symbol_changed")
            token.symbol = symbol
        if decimals is not None and decimals != token.decimals:
            warnings.append("decimals_mismatch")
            token.decimals = decimals
        token.total_supply = str(total_supply) if total_supply is not None else None
        token.supply_cap = str(supply_cap) if supply_cap is not None else None
        token.paused_features = ",".join(map(str, paused)) if paused else ""
        if paused:
            warnings.append(f"paused_features={token.paused_features}")
    except Exception as exc:
        warnings.append(f"metadata_call_failed:{str(exc)[:80]}")

    token.warnings = ";".join(warnings)
    return token


def is_range_too_large(exc: Exception) -> bool:
    text = str(exc).lower()
    return "range is too large" in text or "block range is too large" in text or "query returned more than" in text


def scan(
    rpc: RpcClient,
    from_block: int,
    to_block: int,
    chunk_size: int,
    enrich: bool,
    min_chunk_size: int,
    progress: Any | None = None,
) -> list[B20Token]:
    tokens: list[B20Token] = []
    current = from_block
    active_chunk_size = max(1, chunk_size)
    min_chunk_size = max(1, min_chunk_size)
    while current <= to_block:
        end = min(current + active_chunk_size - 1, to_block)
        try:
            logs = rpc.get_logs(current, end)
        except Exception as exc:
            if is_range_too_large(exc) and active_chunk_size > min_chunk_size:
                next_chunk_size = max(min_chunk_size, active_chunk_size // 2)
                message = (
                    f"RPC rejected block range {current}-{end}; reducing chunk size "
                    f"from {active_chunk_size} to {next_chunk_size}"
                )
                if progress:
                    progress(message)
                print(message, file=sys.stderr, flush=True)
                active_chunk_size = next_chunk_size
                continue
            raise
        message = f"scanned blocks {current}-{end}: {len(logs)} B20Created logs"
        if progress:
            progress(message)
        print(message, file=sys.stderr, flush=True)
        for log in logs:
            try:
                token = decode_b20_created(log)
                if enrich:
                    token = enrich_token(rpc, token)
                tokens.append(token)
            except Exception as exc:
                print(f"warning: failed to decode log {log.get('transactionHash')}: {exc}", file=sys.stderr)
        current = end + 1
        if active_chunk_size < chunk_size and len(logs) == 0:
            active_chunk_size = min(chunk_size, active_chunk_size * 2)
    tokens.sort(key=lambda t: (t.block_number, t.log_index), reverse=True)
    return tokens


def token_rows(tokens: list[B20Token]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for token in tokens:
        buy_url = f"{UNISWAP_BASE}&inputCurrency={USDC_BASE}&outputCurrency={token.address}"
        sell_url = f"{UNISWAP_BASE}&inputCurrency={token.address}&outputCurrency={USDC_BASE}"
        rows.append(
            {
                "block_number": str(token.block_number),
                "tx_hash": token.tx_hash,
                "address": token.address,
                "variant": token.variant,
                "name": token.name,
                "symbol": token.symbol,
                "decimals": str(token.decimals),
                "total_supply": token.total_supply or "",
                "supply_cap": token.supply_cap or "",
                "paused_features": token.paused_features or "",
                "warnings": token.warnings,
                "source": token.source,
                "basescan": BASESCAN_TOKEN + token.address,
                "buy_url": buy_url,
                "sell_url": sell_url,
            }
        )
    return rows


def write_csv(path: Path, tokens: list[B20Token]) -> None:
    rows = token_rows(tokens)
    fields = [
        "block_number",
        "tx_hash",
        "address",
        "variant",
        "name",
        "symbol",
        "decimals",
        "total_supply",
        "supply_cap",
        "paused_features",
        "warnings",
        "source",
        "basescan",
        "buy_url",
        "sell_url",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fields)
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, tokens: list[B20Token]) -> None:
    path.write_text(json.dumps(token_rows(tokens), indent=2, ensure_ascii=False), encoding="utf-8")


def js_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def write_html(path: Path, tokens: list[B20Token]) -> None:
    rows = []
    for token in tokens:
        buy_url = f"{UNISWAP_BASE}&inputCurrency={USDC_BASE}&outputCurrency={token.address}"
        sell_url = f"{UNISWAP_BASE}&inputCurrency={token.address}&outputCurrency={USDC_BASE}"
        rows.append(
            f"""
            <tr>
              <td>{html.escape(token.symbol)}</td>
              <td>{html.escape(token.name)}</td>
              <td>{html.escape(token.variant)}</td>
              <td><code>{html.escape(token.address)}</code></td>
              <td>{html.escape(str(token.decimals))}</td>
              <td>{html.escape(token.warnings or "")}</td>
              <td class="actions">
                <button onclick='addToken({js_string(token.address)}, {js_string(token.symbol)}, {token.decimals})'>导入</button>
                <a href="{html.escape(buy_url)}" target="_blank" rel="noreferrer">买入</a>
                <a href="{html.escape(sell_url)}" target="_blank" rel="noreferrer">卖出</a>
                <a href="{BASESCAN_TOKEN}{html.escape(token.address)}" target="_blank" rel="noreferrer">查看</a>
              </td>
            </tr>
            """
        )

    page = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>B20 代币扫描器</title>
  <style>
    :root {{ color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; }}
    body {{ margin: 24px; }}
    h1 {{ font-size: 24px; margin: 0 0 12px; }}
    p {{ max-width: 900px; color: #666; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ border-bottom: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ position: sticky; top: 0; background: Canvas; }}
    code {{ font-size: 12px; word-break: break-all; }}
    button, a {{ display: inline-flex; align-items: center; min-height: 32px; padding: 0 10px; border: 1px solid #aaa; border-radius: 6px; background: Canvas; color: CanvasText; text-decoration: none; cursor: pointer; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .toolbar {{ display: flex; gap: 8px; align-items: center; margin: 16px 0; }}
    input {{ min-height: 32px; padding: 0 10px; width: min(520px, 80vw); }}
  </style>
</head>
<body>
  <h1>B20 代币扫描器</h1>
  <p>只读扫描结果。导入按钮会把代币添加到浏览器钱包；买入/卖出会打开 Base 链上的 Uniswap，最终交易仍需要你在钱包里确认。</p>
  <div class="toolbar">
    <input id="filter" placeholder="按名称、符号、合约地址或风险提示过滤" oninput="filterRows()" />
    <span>共 {len(tokens)} 个代币</span>
  </div>
  <table>
    <thead>
      <tr>
        <th>符号</th><th>名称</th><th>类型</th><th>合约地址</th><th>精度</th><th>风险提示</th><th>操作</th>
      </tr>
    </thead>
    <tbody id="rows">
      {''.join(rows)}
    </tbody>
  </table>
  <script>
    async function addToken(address, symbol, decimals) {{
      if (!window.ethereum) {{
        alert('没有检测到浏览器钱包，请先安装或启用钱包插件。');
        return;
      }}
      await window.ethereum.request({{
        method: 'wallet_switchEthereumChain',
        params: [{{ chainId: '0x2105' }}],
      }}).catch(async (err) => {{
        if (err.code === 4902) {{
          await window.ethereum.request({{
            method: 'wallet_addEthereumChain',
            params: [{{
              chainId: '0x2105',
              chainName: 'Base',
              nativeCurrency: {{ name: 'Ether', symbol: 'ETH', decimals: 18 }},
              rpcUrls: ['https://mainnet.base.org'],
              blockExplorerUrls: ['https://basescan.org']
            }}],
          }});
        }} else {{
          throw err;
        }}
      }});
      await window.ethereum.request({{
        method: 'wallet_watchAsset',
        params: {{
          type: 'ERC20',
          options: {{ address, symbol, decimals }}
        }}
      }});
    }}
    function filterRows() {{
      const q = document.getElementById('filter').value.toLowerCase();
      for (const row of document.querySelectorAll('#rows tr')) {{
        row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
      }}
    }}
  </script>
</body>
</html>
"""
    path.write_text(page, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan Base B20 tokens from B20Factory logs.")
    parser.add_argument("--rpc", required=True, help="Base mainnet RPC URL")
    parser.add_argument("--from-block", type=int, help="Start block. Use an archive RPC for older ranges.")
    parser.add_argument("--to-block", type=int, help="End block. Defaults to latest.")
    parser.add_argument("--last", type=int, help="Scan only the last N blocks.")
    parser.add_argument("--chunk-size", type=int, default=5000, help="eth_getLogs block chunk size")
    parser.add_argument("--min-chunk-size", type=int, default=10, help="Smallest adaptive eth_getLogs chunk size")
    parser.add_argument("--no-enrich", action="store_true", help="Skip metadata calls")
    parser.add_argument("--out", default="b20_tokens.csv", help="CSV output path")
    parser.add_argument("--json", default="b20_tokens.json", help="JSON output path")
    parser.add_argument("--html", default="b20_tokens.html", help="HTML dashboard output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rpc = RpcClient(args.rpc)
    latest = args.to_block or rpc.block_number()
    if args.last is not None:
        from_block = max(0, latest - args.last + 1)
    else:
        from_block = args.from_block if args.from_block is not None else max(0, latest - 10_000 + 1)
    if from_block > latest:
        raise SystemExit(f"from-block {from_block} is greater than latest {latest}")

    tokens = scan(
        rpc,
        from_block,
        latest,
        args.chunk_size,
        enrich=not args.no_enrich,
        min_chunk_size=args.min_chunk_size,
    )
    write_csv(Path(args.out), tokens)
    write_json(Path(args.json), tokens)
    write_html(Path(args.html), tokens)

    print(f"Found {len(tokens)} B20 tokens")
    print(f"CSV:  {Path(args.out).resolve()}")
    print(f"JSON: {Path(args.json).resolve()}")
    print(f"HTML: {Path(args.html).resolve()}")
    if tokens:
        print("\nLatest tokens:")
        for token in tokens[:10]:
            warn = f" [{token.warnings}]" if token.warnings else ""
            print(f"- {token.symbol} | {token.name} | {token.address}{warn}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
