# 🔐 SSH KeyTool

> 纯前端 SSH 密钥工具箱 — 浏览器本地运算，数据零上传

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Vue 3](https://img.shields.io/badge/Vue-3.x-42b883.svg)](https://vuejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6.svg)](https://typescriptlang.org)

---

## ✨ 功能

| 功能 | 描述 |
|------|------|
| 🔑 **密钥生成** | 支持 RSA 2048/4096、ECDSA P-256/P-384/P-521、Ed25519 |
| 🔍 **密钥解析** | 解析任意 SSH 公钥，显示类型、长度、指纹等详细信息 |
| 🧮 **指纹计算** | 计算 SHA256 和 MD5 指纹，用于服务器身份验证 |
| 🔄 **格式转换** | OpenSSH 公钥 ↔ PEM（SPKI）格式互转 |
| 📤 **提取公钥** | 从 OpenSSH/RSA PEM 私钥中提取对应公钥 |

## 🔒 隐私安全

- **纯前端运算**：所有密钥生成和处理完全在浏览器本地完成
- **数据零上传**：私钥内容永远不会离开你的设备
- **可离线使用**：构建后无需网络即可运行
- **无后端服务**：静态页面，可自行部署到任何平台

## 🚀 快速开始

```bash
# 安装依赖
npm install

# 本地开发
npm run dev

# 构建生产版本
npm run build
```

## 🛠 技术栈

- **框架**：Vue 3 + TypeScript + Vite
- **UI**：Element Plus + Tailwind CSS v4
- **密码库**：
  - `node-forge` — RSA 密钥生成与 PEM 格式处理
  - `@noble/ed25519` — Ed25519 密钥生成（RFC 8032）
  - Web Crypto API — ECDSA 密钥生成与 SHA256 指纹计算

## 📖 支持的密钥格式

**私钥（输入）**
```
-----BEGIN OPENSSH PRIVATE KEY-----   # OpenSSH 新格式（RSA/ECDSA/Ed25519）
-----BEGIN RSA PRIVATE KEY-----       # RSA PKCS#1 PEM
-----BEGIN PRIVATE KEY-----           # PKCS#8 PEM
```

**公钥（输出/输入）**
```
ssh-rsa AAAA...                       # RSA 公钥（authorized_keys 格式）
ssh-ed25519 AAAA...                   # Ed25519 公钥
ecdsa-sha2-nistp256 AAAA...           # ECDSA P-256 公钥
-----BEGIN PUBLIC KEY-----            # PEM SPKI 格式
```

## 🌐 部署

```bash
npm run build
# 将 dist/ 目录部署到任意静态托管：
# GitHub Pages / Vercel / Netlify / Cloudflare Pages
```

## 📄 License

MIT © [nanjingya](https://github.com/nanjingya)
