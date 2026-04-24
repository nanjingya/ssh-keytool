# 🔐 SSH KeyTool

> 纯前端 SSH 密钥工具箱 — 浏览器本地运算，数据零上传

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Vue 3](https://img.shields.io/badge/Vue-3.x-42b883.svg)](https://vuejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6.svg)](https://typescriptlang.org)

---

## ✨ 功能

| 功能 | 描述 |
|------|------|
| 🔑 **密钥生成** | 支持 RSA 2048/4096、ECDSA P-256/P-384/P-521、Ed25519；可选密码短语加密私钥 |
| 🔍 **密钥解析** | 解析任意 SSH 公钥，显示类型、长度、指纹等详细信息，严格校验格式 |
| 🧮 **指纹计算** | 计算 SHA256 和 MD5 指纹，支持完整公钥或纯 Base64 blob 输入 |
| 🔄 **格式转换** | OpenSSH 公钥 ↔ PEM（SPKI）格式互转，支持 RSA / ECDSA / Ed25519 |
| 📤 **提取公钥** | 从 OpenSSH/RSA PEM 私钥中提取对应公钥 |

## 🔒 隐私安全

- **纯前端运算**：所有操作在浏览器本地完成，私钥永远不离开你的设备
- **数据零上传**：无后端服务，无日志，无追踪
- **可离线使用**：构建后无需网络即可运行
- **开源可审计**：代码完全公开，可自行部署

---

## 📸 界面预览

### 密钥生成
支持 6 种算法，可选密码短语加密私钥（bcrypt-pbkdf + AES-256-CTR），实时强度评估

![密钥生成](./screenshots/key-generator.png)

### 密钥解析
严格校验 Blob 边界与字段，解析类型、长度、安全级别、SHA256/MD5 指纹

![密钥解析](./screenshots/key-inspector.png)

### 指纹计算
支持粘贴完整公钥或纯 Base64 blob，同时输出 SHA256（现代）和 MD5（旧版兼容）指纹

![指纹计算](./screenshots/fingerprint.png)

### 格式转换
OpenSSH 公钥 ↔ PEM SPKI 互转，覆盖 RSA、ECDSA P-256/P-384/P-521、Ed25519

![格式转换](./screenshots/format-converter.png)

### 提取公钥
从私钥（OpenSSH / RSA PEM / PKCS#8）中提取 authorized_keys 格式公钥

![提取公钥](./screenshots/extract-pubkey.png)

---

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
  - `bcrypt-pbkdf` — OpenSSH `bcrypt` KDF（私钥加密）

## 🔐 私钥加密说明

生成私钥时可设置密码短语（Passphrase）：

- **不设置**：输出明文 OpenSSH 私钥（不推荐，文件泄露即意味着访问权限暴露）
- **设置后**：使用 OpenSSH 标准加密格式，与 `ssh-add`、`ssh-keygen` 等工具完全兼容

```
KDF:    bcrypt-pbkdf（rounds=16）
Cipher: aes256-ctr
```

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

## ✅ 浏览器兼容性

| 功能 | 要求 |
|------|------|
| 密钥生成 / 指纹计算 | Chrome 90+ / Firefox 90+ / Safari 15+ |
| Ed25519 PEM 导出 | Chrome 130+ / Firefox 130+ / Safari 17+ |
| ECDSA 操作 | 需 HTTPS 或 localhost 环境 |

## 🌐 部署

```bash
npm run build
# 将 dist/ 目录部署到任意静态托管：
# GitHub Pages / Vercel / Netlify / Cloudflare Pages
```

## 📄 License

MIT © [nanjingya](https://github.com/nanjingya)
