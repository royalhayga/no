# 🌐 TVTV - 自动化节点聚合、去重、三 DNS 墙检测、204 实测与精简/全量双模版系统

本项目是一个基于 **GitHub Actions** 的自动化节点处理与订阅净化平台。系统将节点流转与模版合成进行了完全解耦，并提供 Full (全量版) 与 Elite (精简极速版) 双规则模版：

---

## 📊 解耦订阅文件入口一览

| 订阅类型 | 文件路径 | 适用场景说明 |
| :--- | :--- | :--- |
| **纯节点 Clash 订阅** | `output/clash.yaml` | **纯纯净净的节点池**，不含复杂分流规则，适合作为第三方 `proxy-provider` 引入到 OpenClash / 路由器本地。 |
| **全量规则 Clash 订阅 (Full)** | `output/clash_rules.yaml` | **全量规则版本**，内置 11 阶路由法则、50+ 规则源与 40+ 业务策略组（含双层负载均衡），适合全业务覆盖。 |
| **精简极速 Clash 订阅 (Elite)** | `output/clash_elite_rules.yaml` | **精简极速版本**，剔除冷门小众品牌，专注核心高频业务（YouTube, Google, OpenAI, Telegram, Twitter, Netflix, Github, Steam 等），更省内存更稳定。 |
| **Base64 通用订阅** | `output/sub.txt` | 适用于 V2RayN、Shadowrocket（小火箭）、Quantumult X 等通用客户端。 |
| **Sing-box 订阅** | `output/singbox.json` | 适用于 Sing-box / NekoBox / Hiddify 客户端。 |
| **明文节点列表** | `output/nodes.txt` | 节点 URL 明文列表。 |

---

## 🌍 按国家/地区分流订阅链接 (`output/by_country/`)

支持按国家/地区单独订阅特定节点的链接（如仅订阅香港节点、仅订阅日本节点等）：

- 🇭🇰 **香港节点 (HK)**: `https://raw.githubusercontent.com/<user>/<repo>/master/output/by_country/HK/clash.yaml`
- 🇯🇵 **日本节点 (JP)**: `https://raw.githubusercontent.com/<user>/<repo>/master/output/by_country/JP/clash.yaml`
- 🇺🇸 **美国节点 (US)**: `https://raw.githubusercontent.com/<user>/<repo>/master/output/by_country/US/clash.yaml`
- 🇸🇬 **新加坡节点 (SG)**: `https://raw.githubusercontent.com/<user>/<repo>/master/output/by_country/SG/clash.yaml`
- 🇹🇼 **台湾节点 (TW)**: `https://raw.githubusercontent.com/<user>/<repo>/master/output/by_country/TW/clash.yaml`
- 🇰🇷 **韩国节点 (KR)**: `https://raw.githubusercontent.com/<user>/<repo>/master/output/by_country/KR/clash.yaml`
- 🇬🇧 **英国节点 (UK)**: `https://raw.githubusercontent.com/<user>/<repo>/master/output/by_country/UK/clash.yaml`
- 🇩🇪 **德国节点 (DE)**: `https://raw.githubusercontent.com/<user>/<repo>/master/output/by_country/DE/clash.yaml`

---

## ⚖️ 免责声明 (Disclaimer)

本项目仅作为 GitHub Actions 自动化数据处理的技术演示与交流使用。所有资源均搜集自公开互联网，项目本身不存储、不产生任何实质加密通信流量。请使用者严格遵守所在国家/地区的法律法规，勿用于非法用途。
