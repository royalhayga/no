# 🌐 TVTV - 自动化节点聚合、去重、三 DNS 墙检测与 204 出海实测系统

本项目是一个基于 **GitHub Actions** 的自动化节点处理与订阅净化平台。系统将节点流转拆分为 **5 个独立递进的阶段 (Index / Stage)**，每个阶段均包含独立的 GitHub Action 工作流与独立的格式导出目录。

---

## 📊 阶段划分与输出目录结构

每一阶段均独立输出 5 种全套格式文件：
- `nodes.txt`：明文节点链接列表 (`vmess://`, `vless://`, `ss://`, `ssr://`, `trojan://`, `hysteria2://`, `tuic://`)
- `sub.txt`：Base64 编码通用订阅
- `clash.yaml`：Clash / Mihomo / OpenClash 订阅配置
- `singbox.json`：Sing-box / NekoBox 订阅配置
- `summary.json`：数据统计摘要

| 阶段 | Actions 工作流配置文件 | 对应的 Python 脚本 | 输出规范目录 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| **阶段一：汇总** | `.github/workflows/aggregate.yml` | `scripts/aggregate.py` | `output/raw/` | 扫描 `ref/` 目录下 28 个开源仓库全量文件，保留所有原始节点 |
| **阶段二：去重** | `.github/workflows/dedupe.yml` | `scripts/dedupe.py` | `output/deduped/` | 按传输属性生成 SHA256 哈希指纹主去重，并生成 `alias_report.json` 别名碰撞报告 |
| **阶段三：DNS** | `.github/workflows/dns.yml` | `scripts/dns.py` | `output/dns/` | 对比阿里 `223.5.5.5`、DNSPod `119.29.29.29` 与 Cloudflare `1.1.1.1`，剔除 GFW 假 IP 污染与域名阻断 |
| **阶段四：Socket** | `.github/workflows/socket.yml` | `scripts/socket.py` | `output/socket/` | 高并发 TCP 建连、TLS 握手及 QUIC RFC 9000 Initial 探针，剔除死端口节点 |
| **阶段五：204实测** | `.github/workflows/verified.yml` | `scripts/verified.py` | `output/verified/`<br>(及 `output/` 根目录) | 在 GitHub Actions 中拉起 **Mihomo (Clash Meta)** 内核，发包至 `generate_204` 测试真实翻墙能力 |

---

## 🚀 最终生产订阅链接 (Stage 5 最终可用)

推送至 GitHub 仓库后，即可使用以下链接引入客户端：

| 类型 | 订阅 URL 地址 |
| :--- | :--- |
| **Clash / Mihomo** | `https://raw.githubusercontent.com/<user>/<repo>/master/output/clash.yaml` |
| **Base64 通用订阅** | `https://raw.githubusercontent.com/<user>/<repo>/master/output/sub.txt` |
| **Sing-box** | `https://raw.githubusercontent.com/<user>/<repo>/master/output/singbox.json` |
| **明文节点列表** | `https://raw.githubusercontent.com/<user>/<repo>/master/output/nodes.txt` |

---

## ⚖️ 免责声明 (Disclaimer)

本项目仅作为 GitHub Actions 自动化数据处理的技术演示与交流使用。所有资源均搜集自公开互联网，项目本身不存储、不产生任何实质加密通信流量。请使用者严格遵守所在国家/地区的法律法规，勿用于非法用途。
