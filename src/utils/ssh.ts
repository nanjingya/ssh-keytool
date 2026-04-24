import forge from 'node-forge'
import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha2.js'

// Enable sync mode for @noble/ed25519 v3
ed.hashes.sha512 = sha512

export type KeyType = 'RSA-2048' | 'RSA-4096' | 'ECDSA-P256' | 'ECDSA-P384' | 'ECDSA-P521' | 'Ed25519'

export interface SSHKeyPair {
  privateKey: string
  publicKey: string
  fingerprint: { sha256: string; md5: string }
  info: { type: string; bits?: number; curve?: string; comment: string }
}

export interface ParsedPublicKey {
  type: string
  comment: string
  blob: Uint8Array
  details: Record<string, string>
  fingerprint: { sha256: string; md5: string }
}

// ── SSH wire-format helpers ─────────────────────────────────────────────────

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrays) { out.set(a, off); off += a.length }
  return out
}

function u32(n: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, false)
  return b
}

function lv(data: Uint8Array): Uint8Array {
  return concat(u32(data.length), data)
}

function sshStr(s: string): Uint8Array {
  return lv(new TextEncoder().encode(s))
}

function mpint(n: bigint): Uint8Array {
  if (n === 0n) return lv(new Uint8Array(0))
  let hex = n.toString(16)
  if (hex.length % 2) hex = '0' + hex
  const bytes = Uint8Array.from(hex.match(/.{2}/g)!.map(h => parseInt(h, 16)))
  const data = bytes[0] & 0x80 ? concat(new Uint8Array([0]), bytes) : bytes
  return lv(data)
}

function b64Encode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
}

function b64Decode(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
}

function forgeBigIntToNative(bi: forge.jsbn.BigInteger): bigint {
  return BigInt('0x' + bi.toString(16))
}

// ── Public key blob builders ────────────────────────────────────────────────

function rsaPublicBlob(e: bigint, n: bigint): Uint8Array {
  return concat(sshStr('ssh-rsa'), mpint(e), mpint(n))
}

function ecdsaPublicBlob(curveName: string, point: Uint8Array): Uint8Array {
  return concat(sshStr(`ecdsa-sha2-${curveName}`), sshStr(curveName), lv(point))
}

function ed25519PublicBlob(pub: Uint8Array): Uint8Array {
  return concat(sshStr('ssh-ed25519'), lv(pub))
}

// ── OpenSSH private key builder (unencrypted) ───────────────────────────────

function buildOpenSSHPrivateKey(pubBlob: Uint8Array, privParts: Uint8Array, comment: string): string {
  const check = Math.floor(Math.random() * 0xFFFFFFFF)
  const body = concat(u32(check), u32(check), privParts, sshStr(comment))

  const rem = body.length % 8
  const padding = rem ? new Uint8Array(8 - rem).map((_, i) => i + 1) : new Uint8Array(0)
  const padded = concat(body, padding)

  const raw = concat(
    new TextEncoder().encode('openssh-key-v1\0'),
    sshStr('none'),
    sshStr('none'),
    lv(new Uint8Array(0)),
    u32(1),
    lv(pubBlob),
    lv(padded),
  )

  const b64 = b64Encode(raw).match(/.{1,70}/g)!.join('\n')
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`
}

// ── Fingerprint ─────────────────────────────────────────────────────────────

async function fingerprintFromBlob(blob: Uint8Array): Promise<{ sha256: string; md5: string }> {
  const hashBuf = await crypto.subtle.digest('SHA-256', blob.buffer as ArrayBuffer)
  const sha256 = 'SHA256:' + b64Encode(new Uint8Array(hashBuf)).replace(/=+$/, '')

  const md = forge.md.md5.create()
  md.update(forge.util.binary.raw.encode(blob))
  const md5 = md.digest().toHex().match(/.{2}/g)!.join(':')

  return { sha256, md5 }
}

// ── RSA key generation ──────────────────────────────────────────────────────

export function generateRSA(bits: 2048 | 4096, comment = 'ssh-keytool'): Promise<SSHKeyPair> {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits, workers: -1 }, async (err, kp) => {
      if (err) return reject(err)

      const n = forgeBigIntToNative(kp.publicKey.n)
      const e = forgeBigIntToNative(kp.publicKey.e)
      const d = forgeBigIntToNative(kp.privateKey.d)
      const p = forgeBigIntToNative(kp.privateKey.p)
      const q = forgeBigIntToNative(kp.privateKey.q)
      const iqmp = forgeBigIntToNative(kp.privateKey.qInv)

      const pubBlob = rsaPublicBlob(e, n)
      const privParts = concat(
        sshStr('ssh-rsa'),
        mpint(n), mpint(e), mpint(d), mpint(iqmp), mpint(p), mpint(q),
      )

      const privateKey = buildOpenSSHPrivateKey(pubBlob, privParts, comment)
      const publicKey = `ssh-rsa ${b64Encode(pubBlob)} ${comment}`
      const fingerprint = await fingerprintFromBlob(pubBlob)

      resolve({ privateKey, publicKey, fingerprint, info: { type: 'RSA', bits, comment } })
    })
  })
}

// ── ECDSA key generation ────────────────────────────────────────────────────

const EC_CURVES: Record<string, { namedCurve: string; sshName: string; bits: number }> = {
  'P-256': { namedCurve: 'P-256', sshName: 'nistp256', bits: 256 },
  'P-384': { namedCurve: 'P-384', sshName: 'nistp384', bits: 384 },
  'P-521': { namedCurve: 'P-521', sshName: 'nistp521', bits: 521 },
}

export async function generateECDSA(
  curve: 'P-256' | 'P-384' | 'P-521',
  comment = 'ssh-keytool',
): Promise<SSHKeyPair> {
  const { namedCurve, sshName, bits } = EC_CURVES[curve]
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, ['sign', 'verify'])

  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey)

  // base64url → bigint
  const dB64 = jwk.d!.replace(/-/g, '+').replace(/_/g, '/')
  const dPadded = dB64.padEnd(Math.ceil(dB64.length / 4) * 4, '=')
  const dBytes = b64Decode(dPadded)
  const d = BigInt('0x' + Array.from(dBytes).map(b => b.toString(16).padStart(2, '0')).join(''))

  const pubBlob = ecdsaPublicBlob(sshName, rawPub)
  const privParts = concat(
    sshStr(`ecdsa-sha2-${sshName}`),
    sshStr(sshName),
    lv(rawPub),
    mpint(d),
  )

  const privateKey = buildOpenSSHPrivateKey(pubBlob, privParts, comment)
  const publicKey = `ecdsa-sha2-${sshName} ${b64Encode(pubBlob)} ${comment}`
  const fingerprint = await fingerprintFromBlob(pubBlob)

  return { privateKey, publicKey, fingerprint, info: { type: 'ECDSA', bits, curve, comment } }
}

// ── Ed25519 key generation ──────────────────────────────────────────────────

export async function generateEd25519(comment = 'ssh-keytool'): Promise<SSHKeyPair> {
  const { secretKey, publicKey: pub } = ed.keygen()
  const priv64 = concat(secretKey, pub) // 64 bytes: seed(32) + pubkey(32)

  const pubBlob = ed25519PublicBlob(pub)
  const privParts = concat(sshStr('ssh-ed25519'), lv(pub), lv(priv64))

  const privateKey = buildOpenSSHPrivateKey(pubBlob, privParts, comment)
  const publicKey = `ssh-ed25519 ${b64Encode(pubBlob)} ${comment}`
  const fingerprint = await fingerprintFromBlob(pubBlob)

  return { privateKey, publicKey, fingerprint, info: { type: 'Ed25519', comment } }
}

// ── SSH public key parser ───────────────────────────────────────────────────

export async function parsePublicKey(keyStr: string): Promise<ParsedPublicKey> {
  const parts = keyStr.trim().split(/\s+/)
  if (parts.length < 2) throw new Error('无效的 SSH 公钥格式')

  const [type, b64, ...rest] = parts
  const comment = rest.join(' ')

  let blob: Uint8Array
  try {
    blob = b64Decode(b64)
  } catch {
    throw new Error('Base64 解码失败，请检查公钥格式')
  }

  const fingerprint = await fingerprintFromBlob(blob)
  const details: Record<string, string> = {}

  const view = new DataView(blob.buffer, blob.byteOffset)
  let offset = 0

  function readString(): string {
    const len = view.getUint32(offset, false); offset += 4
    const s = new TextDecoder().decode(blob.subarray(offset, offset + len)); offset += len
    return s
  }

  function readBytes(): Uint8Array {
    const len = view.getUint32(offset, false); offset += 4
    const b = blob.subarray(offset, offset + len); offset += len
    return b
  }

  function readMpint(): bigint {
    const bytes = readBytes()
    if (bytes.length === 0) return 0n
    return BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''))
  }

  try {
    const keyType = readString()
    if (keyType !== type) throw new Error(`类型不匹配: ${keyType} vs ${type}`)

    if (type === 'ssh-rsa') {
      const e = readMpint()
      const n = readMpint()
      details['算法'] = 'RSA'
      details['密钥长度'] = `${n.toString(2).length} bits`
      details['公钥指数 (e)'] = e.toString()
    } else if (type.startsWith('ecdsa-sha2-')) {
      const curveName = readString()
      const point = readBytes()
      const curveBits: Record<string, string> = { nistp256: '256', nistp384: '384', nistp521: '521' }
      details['算法'] = 'ECDSA'
      details['曲线'] = curveName
      details['密钥长度'] = `${curveBits[curveName] ?? '?'} bits`
      details['公钥点长度'] = `${point.length} bytes`
    } else if (type === 'ssh-ed25519') {
      const pub = readBytes()
      details['算法'] = 'Ed25519'
      details['密钥长度'] = '256 bits (128-bit security)'
      details['公钥 (hex)'] = Array.from(pub).map(b => b.toString(16).padStart(2, '0')).join('')
    } else {
      details['类型'] = type
    }
  } catch {
    details['解析状态'] = '部分字段解析失败'
  }

  return { type, comment, blob, details, fingerprint }
}

// ── Extract public key from private key ─────────────────────────────────────

export async function extractPublicKey(privKeyPem: string, comment = 'extracted-key'): Promise<string> {
  if (privKeyPem.includes('BEGIN OPENSSH PRIVATE KEY')) {
    return extractFromOpenSSH(privKeyPem, comment)
  }
  if (
    privKeyPem.includes('BEGIN RSA PRIVATE KEY') ||
    privKeyPem.includes('BEGIN PRIVATE KEY')
  ) {
    try {
      const privKey = forge.pki.privateKeyFromPem(privKeyPem) as forge.pki.rsa.PrivateKey
      const n = forgeBigIntToNative(privKey.n)
      const e = forgeBigIntToNative(privKey.e)
      const pubBlob = rsaPublicBlob(e, n)
      return `ssh-rsa ${b64Encode(pubBlob)} ${comment}`
    } catch {
      throw new Error('RSA 私钥解析失败，请确认格式正确')
    }
  }
  throw new Error('不支持的私钥格式，请输入 OpenSSH 或 RSA PEM 格式的私钥')
}

function extractFromOpenSSH(pem: string, comment: string): string {
  const b64 = pem
    .replace('-----BEGIN OPENSSH PRIVATE KEY-----', '')
    .replace('-----END OPENSSH PRIVATE KEY-----', '')
    .replace(/\s/g, '')
  const raw = b64Decode(b64)

  const magic = new TextDecoder().decode(raw.subarray(0, 15))
  if (magic !== 'openssh-key-v1\0') throw new Error('非标准 OpenSSH 私钥格式')

  let offset = 15
  const view = new DataView(raw.buffer, raw.byteOffset)

  function readU32(): number {
    const v = view.getUint32(offset, false); offset += 4; return v
  }
  function skip() { const len = readU32(); offset += len }
  function readBytes(): Uint8Array {
    const len = readU32()
    const b = raw.subarray(offset, offset + len); offset += len; return b
  }

  skip() // cipher
  skip() // kdf
  skip() // kdf options
  if (readU32() === 0) throw new Error('私钥中不包含密钥')

  const pubBlob = readBytes()
  const typeLen = new DataView(pubBlob.buffer, pubBlob.byteOffset).getUint32(0, false)
  const keyType = new TextDecoder().decode(pubBlob.subarray(4, 4 + typeLen))

  return `${keyType} ${b64Encode(pubBlob)} ${comment}`
}

// ── Format conversion ────────────────────────────────────────────────────────

export function pemToOpenSSHPublic(pem: string): string {
  try {
    const pubKey = forge.pki.publicKeyFromPem(pem) as forge.pki.rsa.PublicKey
    const n = forgeBigIntToNative(pubKey.n)
    const e = forgeBigIntToNative(pubKey.e)
    const blob = rsaPublicBlob(e, n)
    return `ssh-rsa ${b64Encode(blob)} converted-key`
  } catch {
    throw new Error('公钥 PEM 解析失败，请确认格式正确（当前仅支持 RSA 公钥）')
  }
}

export function opensshPublicToPem(sshPubKey: string): string {
  const parts = sshPubKey.trim().split(/\s+/)
  if (parts.length < 2 || parts[0] !== 'ssh-rsa') {
    throw new Error('当前仅支持 RSA 公钥转换（ssh-rsa 格式）')
  }
  const blob = b64Decode(parts[1])
  const view = new DataView(blob.buffer, blob.byteOffset)
  let offset = 0

  function readMpintHex(): string {
    const len = view.getUint32(offset, false); offset += 4
    const bytes = blob.subarray(offset, offset + len); offset += len
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
  }

  const typeLen = view.getUint32(offset, false); offset += 4 + typeLen
  const eHex = readMpintHex()
  const nHex = readMpintHex()

  const e = new forge.jsbn.BigInteger(eHex, 16)
  const n = new forge.jsbn.BigInteger(nHex, 16)
  const pubKey = forge.pki.rsa.setPublicKey(n, e)
  return forge.pki.publicKeyToPem(pubKey)
}
