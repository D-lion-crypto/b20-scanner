# B20 Scanner

一个用于监听 Base B20 代币发布的本地网页面板和命令行扫描器。

项目会同时支持两种发现方式：

- **RPC 实时扫描**：直接监听 Base 新区块里的官方 `B20Created` 事件，速度更快。
- **Coinbase CDP SQL 补漏**：可选使用 Coinbase 的 B20 事件索引做二次校验和补漏，更稳。

本项目默认是只读扫描工具，不读取钱包私钥，也不会在后端自动签名交易。页面里的导入、买入、卖出、B20 创建都会交给浏览器钱包确认。

## 功能

- 实时查看 `B20 Asset` / `B20 Stablecoin` 是否上线。
- 持续扫描 Base 新区块。
- 可选启用 CDP SQL 补漏。
- 显示代币名称、符号、合约地址、来源和快捷操作。
- 支持一键请求钱包导入代币。
- 支持检测到 `B20 Asset` 上线后，自动向官方 B20Factory 提交创建交易并弹出钱包确认。
- 支持导出 CSV / JSON / HTML。

## 安装

```bash
git clone https://github.com/D-lion-crypto/b20-scanner.git
cd b20-scanner
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 启动网页面板

```bash
python b20_web.py
```

浏览器打开：

```text
http://127.0.0.1:8788/
```

推荐用法：

1. 填入 Base 主网 RPC。默认公共 RPC 是 `https://mainnet.base.org`。
2. 可选填写 CDP API Key ID 和 Secret，用来启用 SQL 补漏。
3. 扫描模式选择 `持续扫描新区块`。
4. 点击 `开始扫描`。

如果只想用 RPC 实时扫描，可以不填 CDP 信息。

## 上线后直接创建官方 B20 Asset

网页可以不经过第三方 launch 合约，直接调用官方 B20Factory：

```text
0xB20f000000000000000000000000000000000000
```

调用函数：

```text
createB20(uint8 variant, bytes32 salt, bytes params, bytes[] initCalls)
```

当前页面创建的是 `B20 Asset`，即 `variant = 0`。默认名称和符号都是 `B20`，初始管理员是你连接的钱包地址。

使用步骤：

1. 确认 `B20 名称` 和 `B20 符号`，默认都是 `B20`。
2. 精度默认 `18`，Asset 允许 `6` 到 `18`。
3. `salt` 可以留空，页面会自动生成一个 `bytes32`。
4. 点击 `连接钱包`，确认钱包网络是 Base。
5. 点击 `启用上线后自动创建`。
6. 页面每 3 秒检查一次 `B20 Asset`，一旦返回 `true`，会自动调用钱包弹出创建交易确认。

注意：

- 页面必须一直打开，电脑和浏览器不能休眠。
- 工具不会保存私钥，也不会绕过钱包确认。
- 官方 B20Factory 的创建交易 `value` 是 `0`，不要额外附带 ETH。
- 如果钱包拒绝、余额不足、参数错误或 gas 失败，页面会停止自动创建，需要你检查后重新启用。
- 这个功能只负责在上线瞬间提交创建交易，不负责判断代币参数、流动性或价格风险。

## 命令行扫描

扫描最近 10,000 个区块：

```bash
python b20_scanner.py --rpc https://mainnet.base.org --last 10000
```

输出文件：

- `b20_tokens.csv`
- `b20_tokens.json`
- `b20_tokens.html`

这些文件是本地扫描结果，默认不会提交到 Git。

## B20 判定标准

扫描器只认 Base 官方 B20 Factory 发出的创建事件：

```text
0xB20f000000000000000000000000000000000000
```

事件签名：

```text
B20Created(address indexed token, uint8 indexed variant, string name, string symbol, uint8 decimals, bytes variantEventParams)
```

也就是说：

- 不会因为名字叫 `$B20` 就当成 B20。
- 不会只因为地址以 `0xB200` 开头就当成 B20。
- 只有官方 B20 Factory 创建出来的才会被列为 B20。

## B20 是否上线

B20 上线状态通过 Base 的 Activation Registry 查询：

```text
0x8453000000000000000000000000000000000001
```

功能名：

```text
base.b20_asset
base.b20_stablecoin
```

返回含义：

```text
true  = 该类型 B20 已上线，可以部署
false = 该类型 B20 未上线，调用 Factory 会失败
```

网页面板会自动查询并显示：

- `B20 Asset`
- `B20 Stablecoin`
- 当前区块高度

## CDP SQL 补漏

CDP 是可选功能。启用后，网页后端会在本机用你的 CDP API Key ID 和 Secret 生成短期 JWT，然后请求：

```text
POST https://api.cdp.coinbase.com/platform/v2/data/query/run
```

用途：

- RPC 负责实时扫新区块。
- CDP SQL 负责定期查 Coinbase 的 B20 事件索引，做补漏和校验。

如果不填 CDP 信息，扫描器仍然可以正常用 RPC 工作。

## 安全说明

- 不要提交 CDP API Key、Secret、JSON key 文件、私有 RPC URL、钱包私钥或助记词。
- 如果某个 key 被发到聊天、截图、日志或公开仓库里，请立即 revoke/delete。
- `.gitignore` 已默认排除 `.env`、CDP key 文件、扫描输出和 Python 缓存。
- 本工具只负责发现 B20 创建事件，不判断流动性安全、项目方信誉、价格风险或是否适合买入。

## 许可证

MIT
