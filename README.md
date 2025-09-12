# V2Ray/Clash Config Aggregator

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/VovaplusEXP/p-configs/main.yml?label=Last%20Updated&style=for-the-badge)
![GitHub License](https://img.shields.io/github/license/VovaplusEXP/p-configs?style=for-the-badge)
![GitHub issues](https://img.shields.io/github/issues/VovaplusEXP/p-configs?style=for-the-badge)

This repository provides a collection of high-quality, speed-tested, and regularly updated subscription lists and Clash Meta profiles for V2Ray, Shadowsocks, and Trojan.

The primary goal is to offer clean, reliable, and informative configurations by automatically aggregating, deduplicating, and enriching them from various public sources. The lists are **updated every 6 hours** via GitHub Actions to ensure freshness.

---

## 🤔 How It Works

The entire process is fully automated and involves the following steps:

1.  **📥 Fetch & Deduplicate:** Gathers configs from the subscription list and removes duplicates.
2.  **🚀 Speed Test:** Filters out proxies that are slow or unresponsive using a parallel speed test.
3.  **🔒 Filter Secure:** Creates separate lists for configs that use secure transports like TLS and REALITY.
4.  **📝 Generate Files:** Generates final subscription lists (Base64 and plain text) and Clash Meta profiles.

---

## 🚀 Subscription & Profile Links

All links point to the `main` branch and provide the raw file content.

### 🔵 Clash Meta Profiles

These are advanced profiles for **Clash Meta** clients. They include smart proxy groups (`url-test` and `fallback`) that automatically select the fastest and most reliable server for you.

| Protocol | Profile Link |
| :--- | :--- |
| **VLESS (Secure)** | [vless.yaml](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Clash-Profiles/vless.yaml) |
| **VMess (Secure)** | [vmess.yaml](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Clash-Profiles/vmess.yaml) |
| **Shadowsocks** | [ss.yaml](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Clash-Profiles/ss.yaml) |
| **Trojan** | [trojan.yaml](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Clash-Profiles/trojan.yaml) |

---

### 🟡 Base64 Encoded Subscriptions

Standard Base64 encoded lists, suitable for most clients.

#### Standard Lists
| Protocol | Subscription Link |
| :--- | :--- |
| **VLESS** | [vless.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Base64/vless.txt) |
| **VMess** | [vmess.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Base64/vmess.txt) |
| **Shadowsocks** | [ss.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Base64/ss.txt) |
| **Trojan** | [trojan.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Base64/trojan.txt) |
| **Hysteria2** | [hy2.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Base64/hy2.txt) |
| **TUIC** | [tuic.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Base64/tuic.txt) |

#### Secure Lists (TLS/REALITY only)
| Protocol | Subscription Link |
| :--- | :--- |
| **VLESS (Secure)** | [vless.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Secure-Base64/vless.txt) |
| **VMess (Secure)** | [vmess.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Secure-Base64/vmess.txt) |

---

### ⚪ Plain Text Config Lists

Raw, unencoded config links. Useful for debugging or manual import.

#### Standard Lists
- **VLESS:** [vless.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol/vless.txt)
- **VMess:** [vmess.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol/vmess.txt)
- **Shadowsocks:** [ss.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol/ss.txt)
- **Trojan:** [trojan.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol/trojan.txt)
- **Hysteria2:** [hy2.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol/hy2.txt)
- **TUIC:** [tuic.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol/tuic.txt)

#### Secure Lists (TLS/REALITY only)
- **VLESS (Secure):** [vless.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Secure/vless.txt)
- **VMess (Secure):** [vmess.txt](https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Secure/vmess.txt)

---

## ⚠️ Disclaimer

The configurations provided in this repository are aggregated from public sources on the internet. While the automation aims to filter for functional and fast proxies, their reliability, security, and privacy cannot be guaranteed. Please use them at your own risk.
