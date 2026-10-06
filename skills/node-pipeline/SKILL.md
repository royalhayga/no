---
name: node-pipeline
description: 节点自动化聚合、去重、三 DNS 墙检测、Socket 探针、204 出海实测、GeoIP 分国与双版本 Clash 模版合成系统设计与运维规范。
---

# 节点处理与模版合成系统 (Node Pipeline Skill)

本文档定义了本项目节点自动化流转、去毒清洗、多阶段检测、分国负载均衡以及 Clash 规则模版合成的核心架构与运维规范。

---

## 1. 核心架构与 6 大 Index 处理阶段

### Stage 0: 仓库并发克隆 (`scripts/clone_repos.py`)
- **机制**：读取 `config/sources.json` 登记的 28 个开源仓库。
- **并发优化**：采用 `ThreadPoolExecutor(max_workers=16)` 16 线程并发克隆至 `ref/` 目录，解决云端 Runner 无节点问题。

### Index 1: 多源抓取与数据去毒 (`scripts/aggregate.py`)
- **提取协议**：支持 `vmess://`, `vless://`, `ss://`, `ssr://`, `trojan://`, `hysteria2://`, `tuic://`, Clash YAML。
- **文本与 Markdown 提取**：正则表达式提炼文本及 Markdown 中嵌入的外部 HTTP 订阅链接，自动异步解包。
- **数据安全“去毒” (`sanitize_node`)**：自动过滤局域网/黑洞 IP（`127.0.0.1`, `10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`）及 HTML/XSS 脚本注入，校验端口 `1~65535`。

### Index 2: SHA256 哈希指纹主去重与别名检测 (`scripts/dedupe.py`)
- **过程 2.1 (主去重)**：计算全协议 SHA256 哈希指纹 `SHA256(protocol, server, port, uuid/password, path/sni, public_key)`，**故意排除节点 Name/Remark**，精准合并同节点被改名的情况。
- **过程 2.2 (别名分支)**：排查共享相同 `server + port`（同一台服务器）的潜在别名节点，生成独立的 `output/deduped/alias_report.json` 诊断报告。

### Index 3: 三 DNS 墙与 GFW 污染检测 (`scripts/dns_check.py`)
- **并发比对**：使用 `dnspython` 库开启 100 协程并发查询国内 **阿里云 (`223.5.5.5`)**、**DNSPod (`119.29.29.29`)** 与国外 **Cloudflare (`1.1.1.1`)**。
- **污染拦截**：剔除国内 DNS 查询超时/失败，以及返回 GFW 特征假 IP（`127.0.0.1`, `198.105.x.x`, `59.24.3.173` 等）的节点。

### Index 4: Socket 高并发端口探针 (`scripts/socket_probe.py`)
- **并发探针**：使用 `asyncio.Semaphore(256)` 256 协程高并发、1.5 秒超时探测。
- **全协议覆盖**：TCP 建连、TLS 握手及针对 Hysteria/TUIC 的 RFC 9000 QUIC Initial UDP 探针。

### Index 5: Mihomo 内核出海 204 实测 (`scripts/verified.py`)
- **实测机制**：在 GitHub Actions 中自动拉起 **Mihomo (Clash Meta)** 官方内核，发包至 `http://www.gstatic.com/generate_204` 进行真实代理延迟校验。

### Index 6: GeoIP 分国与全国家一键总订阅 (`scripts/country_split.py`)
- **GeoIP 定位**：批量解析 IP，查询 ip-api 批量接口定位归属国家/地区（HK, JP, US, SG, TW, KR, UK, DE 等）。
- **分目录导出**：在 `output/by_country/` 下为每个国家建立独立子目录（包含全套 5 种格式）。
- **全国家总订阅**：合成包含各国选单的 `output/by_country/all_countries_clash.yaml`。

---

## 2. 动态 Clash 模版合成引擎 (`scripts/template_engine.py`)

### 双层架构与私有节点隔离原则
1. **顶级私有节点隔离**：
   - 模版中用户的顶级私有节点（如 `"手机"`, `"reality funo"`, `"JPreality"`）作为第一优先级保留在策略组开头。
   - **绝对隔离**：私有节点**绝对不加入**任何爬虫节点的 `load-balance` 或 `url-test` 测速池中，保护私有干净 IP。
2. **爬虫分国 `load-balance` 负载均衡组**：
   - 为每个 GeoIP 国家构建 `🇭🇰 香港-负载均衡` (`type: load-balance`, `strategy: round-robin`) 和 `⚡ 全球-全节点负载均衡`。
   - **TVBox 策略组 (`📺 TVBox代理`)**：100% 优先响应 `load-balance` 负载均衡组，满足大流量并发需求。

### 双版本模版输出
- **`output/clash.yaml`**：纯节点池（不做规则混合，纯净订阅）。
- **`output/clash_rules.yaml`**：**Full 全量规则版**（11 阶路由法则 + 50+ 规则源 + 40+ 策略组）。
- **`output/clash_elite_rules.yaml`**：**Elite 精简极速版**（剔除冷门小众品牌 MomoShop/Gucci/WIX 等，专注 YouTube/Google/OpenAI/Telegram/Twitter/Netflix/GitHub/Steam，更低内存更低延迟）。

---

## 3. Git 运维与无感同步原则

1. **绝对静默后台 Rebase**：
   - 每次提交推送，Agent 必须在后台全自动执行 `git fetch origin ; git rebase origin/master ; git push origin master`。
   - **严禁**要求用户手动执行任何 Git 命令或介入冲突排查。
2. **实时无缓冲日志**：
   - 工作流配置 `PYTHONUNBUFFERED: "1"`，所有 Python 脚本 `print()` 设置 `flush=True`，保证 GitHub Actions 控制台日志每秒实时刷新。
3. **单文件安全容量上限**：
   - `export_stage_files` 设置 `max_nodes_per_file = 50000`，确保导出文件体积不超过 30MB，杜绝触发 GitHub 100MB 拒收上限。
