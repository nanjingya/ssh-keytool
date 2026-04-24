import forge from 'node-forge'
import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha2.js'
import bcryptpbkdf from 'bcrypt-pbkdf'
import { Buffer } from 'buffer'

ed.hashes.sha512 = sha512

// ─── Type declarations ──────────────────────────────────────────────────────

export interface SSHKeyPair {
  privateKey: string
  publicKey: string
  fingerprint: { sha256: string; md5: string }
  info: { type: string; bits?: number; curve?: string; comment: string; encrypted: boolean }
}

export interface ParsedPublicKey {
  type: string
  comment: string
  blob: Uint8Array
  details: Record<string, string>
  fingerprint: { sha256: string; md5: string }
}

// ─── Secure random ──────────────────────────────────────────────────────────

function secureRandomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n))
}

function secureRandomU32(): number {
  const b = secureRandomBytes(4)
  return new DataView(b.buffer).getUint32(0, false)
}

// ─── SSH wire-format helpers ─────────────────────────────────────────────────

function concat(...arrays: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = arrays.reduce((n, a) => n + a.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrays) { out.set(a, off); off += a.length }
  return out
}

function u32(n: number): Uint8Array<ArrayBuffer> {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, false)
  return b
}

function lv(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return concat(u32(data.length), data)
}

function sshStr(s: string): Uint8Array<ArrayBuffer> {
  return lv(new TextEncoder().encode(s))
}

// SSH mpint: minimal big-endian with positive sign bit
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

function normalizeBase64(b64: string): string {
  const trimmed = b64.trim()
  const mod = trimmed.length % 4
  if (mod === 0) return trimmed
  return trimmed + '='.repeat(4 - mod)
}

function b64Decode(b64: string): Uint8Array {
  const normalized = normalizeBase64(b64)
  return Uint8Array.from(atob(normalized), c => c.charCodeAt(0))
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')
  return b64Decode(b64)
}

function derToPem(der: Uint8Array, label: string): string {
  const b64 = b64Encode(der).match(/.{1,64}/g)!.join('\n')
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`
}

function forgeBigIntToNative(bi: forge.jsbn.BigInteger): bigint {
  return BigInt('0x' + bi.toString(16))
}

// ─── Strict Blob reader with bounds checking ─────────────────────────────────

class BlobReader {
  private offset = 0
  private readonly data: Uint8Array

  constructor(data: Uint8Array) { this.data = data }

  get remaining() { return this.data.length - this.offset }
  get position() { return this.offset }

  private need(n: number, field: string) {
    if (this.offset + n > this.data.length) {
      throw new Error(
        `解析 "${field}" 越界：需要 ${n} B，剩余 ${this.remaining} B（offset=${this.offset}/${this.data.length}）`
      )
    }
  }

  readU32(field = 'uint32'): number {
    this.need(4, field)
    const v = new DataView(this.data.buffer, this.data.byteOffset + this.offset).getUint32(0, false)
    this.offset += 4
    return v
  }

  readBytes(field: string, maxLen = 65536): Uint8Array {
    const len = this.readU32(`${field}.len`)
    if (len > this.remaining) {
      throw new Error(`"${field}" 声明长度 ${len} B，超出剩余 ${this.remaining} B`)
    }
    if (len > maxLen) {
      throw new Error(`"${field}" 长度 ${len} B 超过安全上限 ${maxLen} B`)
    }
    const b = new Uint8Array(this.data.buffer, this.data.byteOffset + this.offset, len)
    this.offset += len
    return b
  }

  readString(field: string, maxLen = 256): string {
    return new TextDecoder().decode(this.readBytes(field, maxLen))
  }

  // SSH mpint: strips leading sign byte, returns positive bigint
  readMpint(field: string): bigint {
    const bytes = this.readBytes(field, 1040) // max ~8320-bit key
    if (bytes.length === 0) return 0n
    const start = (bytes[0] === 0 && bytes.length > 1) ? 1 : 0
    return BigInt('0x' + Array.from(bytes.subarray(start)).map(b => b.toString(16).padStart(2, '0')).join(''))
  }

  expectString(expected: string, field: string): void {
    const actual = this.readString(field)
    if (actual !== expected) {
      throw new Error(`"${field}" 期望 "${expected}"，实际 "${actual}"`)
    }
  }

  expectEOF(label = 'data'): void {
    if (this.remaining > 0) {
      throw new Error(`${label} 解析完毕后仍剩 ${this.remaining} B 未消耗，数据可能已损坏`)
    }
  }
}

// ─── Public key blob builders ─────────────────────────────────────────────────

function rsaPublicBlob(e: bigint, n: bigint): Uint8Array {
  return concat(sshStr('ssh-rsa'), mpint(e), mpint(n))
}

function ecdsaPublicBlob(curveName: string, point: Uint8Array): Uint8Array {
  return concat(sshStr(`ecdsa-sha2-${curveName}`), sshStr(curveName), lv(point))
}

function ed25519PublicBlob(pub: Uint8Array): Uint8Array {
  return concat(sshStr('ssh-ed25519'), lv(pub))
}

// ─── Fingerprint ──────────────────────────────────────────────────────────────

// Safe copy to guarantee plain ArrayBuffer (avoids SharedArrayBuffer TS errors)
function toArrayBuffer(ua: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(ua.byteLength)
  new Uint8Array(buf).set(ua)
  return buf
}

async function fingerprintFromBlob(blob: Uint8Array): Promise<{ sha256: string; md5: string }> {
  const hashBuf = await crypto.subtle.digest('SHA-256', toArrayBuffer(blob))
  const sha256 = 'SHA256:' + b64Encode(new Uint8Array(hashBuf)).replace(/=+$/, '')

  const md = forge.md.md5.create()
  md.update(forge.util.binary.raw.encode(blob))
  const md5 = md.digest().toHex().match(/.{2}/g)!.join(':')

  return { sha256, md5 }
}

// ─── OpenSSH private key builder (with optional passphrase) ──────────────────
//
// Encrypted format:  cipher=aes256-ctr, kdf=bcrypt (RFC-compatible with OpenSSH)
// Unencrypted format: cipher=none, kdf=none

async function buildOpenSSHPrivateKey(
  pubBlob: Uint8Array,
  privParts: Uint8Array,
  comment: string,
  passphrase?: string,
): Promise<string> {
  // check-int pair must be cryptographically random (prevents oracle attacks)
  const check = secureRandomU32()
  const body = concat(u32(check), u32(check), privParts, sshStr(comment))

  // OpenSSH requires padding to cipher block size.
  // - unencrypted ("none"): treat as 8-byte alignment (OpenSSH convention)
  // - aes256-ctr: 16-byte block size
  const blockSize = (passphrase && passphrase.length > 0) ? 16 : 8
  const rem = body.length % blockSize
  const padding = rem ? new Uint8Array(blockSize - rem).map((_, i) => i + 1) : new Uint8Array(0)
  const padded = concat(body, padding)

  let cipher = 'none'
  let kdf = 'none'
  let kdfOpts = new Uint8Array(0)
  let privSection = padded

  if (passphrase && passphrase.length > 0) {
    cipher = 'aes256-ctr'
    kdf = 'bcrypt'

    const salt = secureRandomBytes(16)
    const rounds = 16 // NIST recommends ≥10; 16 is OpenSSH default

    // bcrypt-pbkdf: derives key (32 B) + IV (16 B) from passphrase
    const derived = Buffer.alloc(48)
    bcryptpbkdf.pbkdf(
      Buffer.from(passphrase, 'utf8'),
      Buffer.byteLength(passphrase, 'utf8'),
      Buffer.from(salt),
      salt.length,
      derived,
      48,
      rounds,
    )

    const encKey = toArrayBuffer(new Uint8Array(derived.buffer, 0, 32))
    const iv     = toArrayBuffer(new Uint8Array(derived.buffer, 32, 16))

    const cryptoKey = await crypto.subtle.importKey('raw', encKey, { name: 'AES-CTR' }, false, ['encrypt'])
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-CTR', counter: new Uint8Array(iv), length: 128 },
      cryptoKey,
      toArrayBuffer(padded),
    )
    privSection = new Uint8Array(encrypted)

    // KDF options wire format: string(salt) + uint32(rounds)
    kdfOpts = concat(lv(salt), u32(rounds))
  }

  const raw = concat(
    new TextEncoder().encode('openssh-key-v1\0'),
    sshStr(cipher),
    sshStr(kdf),
    lv(kdfOpts),
    u32(1),
    lv(pubBlob),
    lv(privSection),
  )

  const b64 = b64Encode(raw).match(/.{1,70}/g)!.join('\n')
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`
}

// ─── RSA key generation ───────────────────────────────────────────────────────

export function generateRSA(
  bits: 2048 | 4096,
  comment = 'ssh-keytool',
  passphrase?: string,
): Promise<SSHKeyPair> {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits, workers: -1 }, async (err, kp) => {
      if (err) return reject(err)
      try {
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

        const privateKey = await buildOpenSSHPrivateKey(pubBlob, privParts, comment, passphrase)
        const publicKey = `ssh-rsa ${b64Encode(pubBlob)} ${comment}`
        const fingerprint = await fingerprintFromBlob(pubBlob)

        resolve({
          privateKey, publicKey, fingerprint,
          info: { type: 'RSA', bits, comment, encrypted: !!passphrase },
        })
      } catch (e) { reject(e) }
    })
  })
}

// ─── ECDSA key generation ─────────────────────────────────────────────────────

const EC_CURVES: Record<string, { namedCurve: string; sshName: string; bits: number }> = {
  'P-256': { namedCurve: 'P-256', sshName: 'nistp256', bits: 256 },
  'P-384': { namedCurve: 'P-384', sshName: 'nistp384', bits: 384 },
  'P-521': { namedCurve: 'P-521', sshName: 'nistp521', bits: 521 },
}

export async function generateECDSA(
  curve: 'P-256' | 'P-384' | 'P-521',
  comment = 'ssh-keytool',
  passphrase?: string,
): Promise<SSHKeyPair> {
  const { namedCurve, sshName, bits } = EC_CURVES[curve]
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, ['sign', 'verify'])

  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey)

  const dB64 = jwk.d!.replace(/-/g, '+').replace(/_/g, '/')
  const dBytes = b64Decode(dB64.padEnd(Math.ceil(dB64.length / 4) * 4, '='))
  const d = BigInt('0x' + Array.from(dBytes).map(b => b.toString(16).padStart(2, '0')).join(''))

  const pubBlob = ecdsaPublicBlob(sshName, rawPub)
  const privParts = concat(sshStr(`ecdsa-sha2-${sshName}`), sshStr(sshName), lv(rawPub), mpint(d))

  const privateKey = await buildOpenSSHPrivateKey(pubBlob, privParts, comment, passphrase)
  const publicKey = `ecdsa-sha2-${sshName} ${b64Encode(pubBlob)} ${comment}`
  const fingerprint = await fingerprintFromBlob(pubBlob)

  return { privateKey, publicKey, fingerprint, info: { type: 'ECDSA', bits, curve, comment, encrypted: !!passphrase } }
}

// ─── Ed25519 key generation ───────────────────────────────────────────────────

export async function generateEd25519(
  comment = 'ssh-keytool',
  passphrase?: string,
): Promise<SSHKeyPair> {
  const { secretKey, publicKey: pub } = ed.keygen()
  const priv64 = concat(secretKey, pub)

  const pubBlob = ed25519PublicBlob(pub)
  const privParts = concat(sshStr('ssh-ed25519'), lv(pub), lv(priv64))

  const privateKey = await buildOpenSSHPrivateKey(pubBlob, privParts, comment, passphrase)
  const publicKey = `ssh-ed25519 ${b64Encode(pubBlob)} ${comment}`
  const fingerprint = await fingerprintFromBlob(pubBlob)

  return { privateKey, publicKey, fingerprint, info: { type: 'Ed25519', comment, encrypted: !!passphrase } }
}

// ─── SSH public key parser (strict) ──────────────────────────────────────────

export async function parsePublicKey(keyStr: string): Promise<ParsedPublicKey> {
  const trimmed = keyStr.trim()
  const parts = trimmed.split(/\s+/)
  if (parts.length < 2) {
    throw new Error('格式错误：SSH 公钥格式应为 "<type> <base64> [comment]"')
  }

  const [type, b64, ...rest] = parts
  const comment = rest.join(' ')

  // Validate base64 alphabet before decode
  if (!/^[A-Za-z0-9+/]+=*$/.test(b64)) {
    throw new Error('Base64 编码含非法字符，请检查公钥是否被截断或损坏')
  }

  let blob: Uint8Array
  try {
    blob = b64Decode(b64)
  } catch (e) {
    throw new Error(`Base64 解码失败：${e}`)
  }

  if (blob.length < 12) {
    throw new Error(`公钥 Blob 仅 ${blob.length} B，过短（最少 12 B）`)
  }

  const fingerprint = await fingerprintFromBlob(blob)
  const details: Record<string, string> = {}
  const reader = new BlobReader(blob)

  // Verify embedded key-type matches the prefix
  const embeddedType = reader.readString('key-type')
  if (embeddedType !== type) {
    throw new Error(`类型不一致：前缀 "${type}"，Blob 内嵌 "${embeddedType}"，公钥可能已损坏`)
  }

  if (type === 'ssh-rsa') {
    const e = reader.readMpint('exponent e')
    const n = reader.readMpint('modulus n')
    const bits = n.toString(2).length

    if (bits < 512 || bits > 16384) {
      throw new Error(`RSA 模数长度 ${bits} bits 不在合法范围（512–16384）`)
    }
    if (e !== 65537n && e !== 3n && e !== 17n && e !== 257n) {
      details['⚠ 公钥指数'] = `${e}（非标准值，通常应为 65537）`
    }
    if (bits < 2048) {
      details['⚠ 安全警告'] = `${bits} bits 低于 NIST 最低推荐（2048 bits）`
    }

    details['算法'] = 'RSA'
    details['密钥长度'] = `${bits} bits`
    details['公钥指数 e'] = e.toString()
    if (reader.remaining > 0) {
      details['⚠ 尾部数据'] = `${reader.remaining} B（可能格式不标准）`
    }

  } else if (type.startsWith('ecdsa-sha2-')) {
    const curveName = reader.readString('curve-name', 32)
    const expectedCurve = type.replace('ecdsa-sha2-', '')
    if (curveName !== expectedCurve) {
      throw new Error(`曲线名不一致：type 前缀为 "${expectedCurve}"，Blob 内嵌 "${curveName}"`)
    }

    const point = reader.readBytes('EC point', 256)
    if (point.length === 0) throw new Error('EC 公钥点为空')
    if (point[0] !== 0x04) {
      throw new Error(
        `EC 公钥点格式字节 0x${point[0].toString(16).padStart(2, '0')} 无效` +
        `（期望 0x04 未压缩格式，0x02/0x03 压缩格式暂不支持）`
      )
    }

    const curveBits: Record<string, string> = { nistp256: '256', nistp384: '384', nistp521: '521' }
    const expectedPointLen: Record<string, number> = { nistp256: 65, nistp384: 97, nistp521: 133 }
    const expLen = expectedPointLen[curveName]
    if (expLen && point.length !== expLen) {
      throw new Error(`${curveName} 公钥点长度应为 ${expLen} B，实际 ${point.length} B`)
    }

    details['算法'] = 'ECDSA'
    details['曲线'] = curveName
    details['密钥长度'] = `${curveBits[curveName] ?? '?'} bits`
    details['安全级别'] = curveName === 'nistp256' ? '128-bit' : curveName === 'nistp384' ? '192-bit' : '260-bit'
    reader.expectEOF('ECDSA 公钥 Blob')

  } else if (type === 'ssh-ed25519') {
    const pub = reader.readBytes('ed25519 pubkey', 64)
    if (pub.length !== 32) {
      throw new Error(`Ed25519 公钥应为 32 B，实际 ${pub.length} B`)
    }
    details['算法'] = 'Ed25519'
    details['密钥长度'] = '256 bits'
    details['安全级别'] = '128-bit（等同于 RSA 3072-bit）'
    details['公钥 (hex)'] = Array.from(pub).map(b => b.toString(16).padStart(2, '0')).join('')
    reader.expectEOF('Ed25519 公钥 Blob')

  } else {
    details['⚠ 未知类型'] = type
    details['提示'] = '仅展示 Base64 Blob，无法深度解析'
  }

  return { type, comment, blob, details, fingerprint }
}

export async function fingerprintFromBase64Blob(base64Blob: string): Promise<{ sha256: string; md5: string }> {
  const b64 = base64Blob.trim()
  if (!/^[A-Za-z0-9+/]+=*$/.test(b64)) {
    throw new Error('Base64 编码含非法字符，请检查是否复制完整')
  }
  const blob = b64Decode(b64)
  if (blob.length < 12) {
    throw new Error(`公钥 Blob 仅 ${blob.length} B，过短（最少 12 B）`)
  }
  return fingerprintFromBlob(blob)
}

// ─── Extract public key from private key ──────────────────────────────────────

export async function extractPublicKey(privKeyPem: string, comment = 'extracted-key'): Promise<string> {
  const trimmed = privKeyPem.trim()

  if (trimmed.includes('BEGIN OPENSSH PRIVATE KEY')) {
    return extractFromOpenSSH(trimmed, comment)
  }
  if (trimmed.includes('BEGIN RSA PRIVATE KEY') || trimmed.includes('BEGIN PRIVATE KEY')) {
    try {
      const privKey = forge.pki.privateKeyFromPem(trimmed) as forge.pki.rsa.PrivateKey
      const n = forgeBigIntToNative(privKey.n)
      const e = forgeBigIntToNative(privKey.e)
      const blob = rsaPublicBlob(e, n)
      return `ssh-rsa ${b64Encode(blob)} ${comment}`
    } catch (e) {
      throw new Error(`RSA 私钥解析失败：${e}`)
    }
  }
  throw new Error('不支持的私钥格式，支持：OpenSSH 格式 / RSA PKCS#1 PEM / PKCS#8 PEM')
}

function extractFromOpenSSH(pem: string, comment: string): string {
  const b64 = pem
    .replace('-----BEGIN OPENSSH PRIVATE KEY-----', '')
    .replace('-----END OPENSSH PRIVATE KEY-----', '')
    .replace(/\s/g, '')
  const raw = b64Decode(b64)

  const magic = new TextDecoder().decode(raw.subarray(0, 15))
  if (magic !== 'openssh-key-v1\0') {
    throw new Error('非标准 OpenSSH 私钥：Magic 头不匹配')
  }

  const reader = new BlobReader(raw.subarray(15))
  reader.readString('cipher')
  reader.readString('kdf')
  reader.readBytes('kdf-options')

  const nkeys = reader.readU32('nkeys')
  if (nkeys === 0) throw new Error('私钥文件中不包含任何密钥')
  if (nkeys > 1) throw new Error(`暂不支持多密钥文件（包含 ${nkeys} 个密钥）`)

  const pubBlob = reader.readBytes('public-key-blob', 2048)

  // Extract key type from blob (first length-prefixed string)
  const blobReader = new BlobReader(pubBlob)
  const keyType = blobReader.readString('key-type')

  return `${keyType} ${b64Encode(pubBlob)} ${comment}`
}

// ─── Format conversion (RSA + ECDSA + Ed25519) ────────────────────────────────

export async function opensshPublicToPem(sshPubKey: string): Promise<string> {
  const parsed = await parsePublicKey(sshPubKey)

  if (parsed.type === 'ssh-rsa') {
    const r = new BlobReader(parsed.blob)
    r.readString('key-type')
    const e = r.readMpint('e')
    const n = r.readMpint('n')
    const pubKey = forge.pki.rsa.setPublicKey(
      new forge.jsbn.BigInteger(n.toString(16), 16),
      new forge.jsbn.BigInteger(e.toString(16), 16),
    )
    return forge.pki.publicKeyToPem(pubKey)
  }

  if (parsed.type.startsWith('ecdsa-sha2-')) {
    const r = new BlobReader(parsed.blob)
    r.readString('key-type')
    const curveName = r.readString('curve-name')
    const point = r.readBytes('EC point')
    r.expectEOF('ECDSA blob')
    const namedCurve = { nistp256: 'P-256', nistp384: 'P-384', nistp521: 'P-521' }[curveName]
    if (!namedCurve) throw new Error(`不支持的曲线：${curveName}`)
    const cryptoKey = await crypto.subtle.importKey(
      'raw', toArrayBuffer(point), { name: 'ECDSA', namedCurve }, true, ['verify'],
    )
    return derToPem(new Uint8Array(await crypto.subtle.exportKey('spki', cryptoKey)), 'PUBLIC KEY')
  }

  if (parsed.type === 'ssh-ed25519') {
    const r = new BlobReader(parsed.blob)
    r.readString('key-type')
    const pub = r.readBytes('pubkey')
    r.expectEOF('Ed25519 blob')
    try {
      const cryptoKey = await crypto.subtle.importKey('raw', toArrayBuffer(pub), { name: 'Ed25519' }, true, ['verify'])
      return derToPem(new Uint8Array(await crypto.subtle.exportKey('spki', cryptoKey)), 'PUBLIC KEY')
    } catch {
      throw new Error('当前浏览器不支持 Ed25519 SPKI 导出（需要 Chrome 130+ / Firefox 130+ / Safari 17+）')
    }
  }

  throw new Error(`不支持的密钥类型 "${parsed.type}"，当前支持：ssh-rsa、ecdsa-sha2-*、ssh-ed25519`)
}

export async function pemToOpenSSHPublic(pem: string): Promise<string> {
  // Try RSA via node-forge
  try {
    const pubKey = forge.pki.publicKeyFromPem(pem) as forge.pki.rsa.PublicKey
    const n = forgeBigIntToNative(pubKey.n)
    const e = forgeBigIntToNative(pubKey.e)
    const blob = rsaPublicBlob(e, n)
    return `ssh-rsa ${b64Encode(blob)} converted-key`
  } catch { /* not RSA, try Web Crypto */ }

  const der = pemToDer(pem)

  // Try ECDSA curves
  for (const [curve, sshName] of [['P-256', 'nistp256'], ['P-384', 'nistp384'], ['P-521', 'nistp521']] as const) {
    try {
      const key = await crypto.subtle.importKey('spki', toArrayBuffer(der), { name: 'ECDSA', namedCurve: curve }, true, ['verify'])
      const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key))
      return `ecdsa-sha2-${sshName} ${b64Encode(ecdsaPublicBlob(sshName, raw))} converted-key`
    } catch { /* try next */ }
  }

  // Try Ed25519
  try {
    const key = await crypto.subtle.importKey('spki', toArrayBuffer(der), { name: 'Ed25519' }, true, ['verify'])
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key))
    return `ssh-ed25519 ${b64Encode(ed25519PublicBlob(raw))} converted-key`
  } catch { /* not Ed25519 either */ }

  throw new Error('无法识别的公钥 PEM 格式（支持 RSA、ECDSA P-256/P-384/P-521、Ed25519）')
}
