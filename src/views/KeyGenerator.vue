<template>
  <div class="page">
    <div class="page-header">
      <h2>SSH 密钥生成</h2>
      <p>在浏览器本地生成 SSH 密钥对，数据不上传服务器</p>
    </div>

    <el-card class="config-card">
      <el-form label-position="top" :model="form">
        <el-row :gutter="24">
          <el-col :span="12">
            <el-form-item label="密钥类型">
              <el-select v-model="form.type" style="width: 100%" @change="onTypeChange">
                <el-option-group label="RSA">
                  <el-option label="RSA 2048-bit（兼容性最好）" value="RSA-2048" />
                  <el-option label="RSA 4096-bit（高安全）" value="RSA-4096" />
                </el-option-group>
                <el-option-group label="ECDSA（椭圆曲线）">
                  <el-option label="ECDSA P-256（256-bit）" value="ECDSA-P256" />
                  <el-option label="ECDSA P-384（384-bit）" value="ECDSA-P384" />
                  <el-option label="ECDSA P-521（521-bit）" value="ECDSA-P521" />
                </el-option-group>
                <el-option-group label="EdDSA">
                  <el-option label="Ed25519（推荐，速度最快）" value="Ed25519" />
                </el-option-group>
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="注释（Comment）">
              <el-input v-model="form.comment" placeholder="user@hostname 或自定义标识" />
            </el-form-item>
          </el-col>
        </el-row>

        <!-- 密码短语 -->
        <el-form-item label="密码短语（Passphrase）">
          <el-input
            v-model="form.passphrase"
            :type="showPass ? 'text' : 'password'"
            placeholder="强烈建议设置，留空则私钥以明文存储"
            @input="onPassphraseChange"
          >
            <template #suffix>
              <el-icon style="cursor:pointer" @click="showPass = !showPass">
                <View v-if="!showPass" /><Hide v-else />
              </el-icon>
            </template>
          </el-input>

          <!-- 强度指示条 -->
          <div v-if="form.passphrase" class="strength-wrap">
            <div class="strength-bar">
              <div
                class="strength-fill"
                :class="strength.cls"
                :style="{ width: strength.pct + '%' }"
              />
            </div>
            <span class="strength-label" :class="strength.cls">{{ strength.label }}</span>
          </div>

          <!-- 无密码警告 -->
          <div v-if="!form.passphrase" class="passphrase-warn">
            <el-icon><Warning /></el-icon>
            未设置密码短语：私钥明文存储，文件泄露即意味着访问权限完全暴露
          </div>
        </el-form-item>

        <div class="algo-hint">
          <el-icon><InfoFilled /></el-icon>
          <span>{{ algoHint }}</span>
        </div>

        <el-button
          type="primary"
          size="large"
          :loading="loading"
          @click="generate"
          style="width: 100%; margin-top: 8px"
        >
          <el-icon v-if="!loading"><Key /></el-icon>
          {{ loading ? '生成中，请稍候...' : '生成密钥对' }}
        </el-button>
      </el-form>
    </el-card>

    <template v-if="result">
      <!-- 密钥信息 -->
      <el-card class="result-card">
        <template #header>
          <div class="card-header">
            <span>密钥信息</span>
            <div style="display:flex;gap:8px">
              <el-tag type="success">生成成功</el-tag>
              <el-tag :type="result.info.encrypted ? 'warning' : 'danger'">
                {{ result.info.encrypted ? '🔒 已加密' : '⚠ 未加密' }}
              </el-tag>
            </div>
          </div>
        </template>
        <el-row :gutter="16">
          <el-col :span="8">
            <div class="info-item">
              <div class="info-label">类型</div>
              <div class="info-value">{{ result.info.type }}</div>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="info-item">
              <div class="info-label">密钥长度</div>
              <div class="info-value">
                {{ result.info.bits ? result.info.bits + ' bits' : (result.info.curve || '256 bits') }}
              </div>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="info-item">
              <div class="info-label">私钥保护</div>
              <div class="info-value" :class="result.info.encrypted ? 'encrypted' : 'plain'">
                {{ result.info.encrypted ? 'AES-256-CTR + bcrypt' : '无（明文）' }}
              </div>
            </div>
          </el-col>
          <el-col :span="12" style="margin-top:12px">
            <div class="info-item">
              <div class="info-label">SHA256 指纹</div>
              <div class="info-value mono">{{ result.fingerprint.sha256 }}</div>
            </div>
          </el-col>
          <el-col :span="12" style="margin-top:12px">
            <div class="info-item">
              <div class="info-label">MD5 指纹</div>
              <div class="info-value mono">{{ result.fingerprint.md5 }}</div>
            </div>
          </el-col>
        </el-row>
      </el-card>

      <!-- 私钥 -->
      <el-card class="result-card">
        <template #header>
          <div class="card-header">
            <span>🔐 私钥（Private Key）</span>
            <div>
              <el-button size="small" @click="copyText(result.privateKey, '私钥')">
                <el-icon><CopyDocument /></el-icon> 复制
              </el-button>
              <el-button size="small" type="primary" @click="download(result.privateKey, 'id_' + typeFilename)">
                <el-icon><Download /></el-icon> 下载
              </el-button>
            </div>
          </div>
        </template>
        <el-alert type="warning" :closable="false" style="margin-bottom:12px">
          <strong>请妥善保管私钥！</strong>
          {{ result.info.encrypted
            ? '此私钥已用密码短语加密（bcrypt-pbkdf + AES-256-CTR），使用时需输入密码短语。'
            : '此私钥未加密，请勿提交到代码仓库或传输至不安全的渠道。'
          }}
        </el-alert>
        <el-input type="textarea" :model-value="result.privateKey" :rows="10" readonly class="mono-area" />
      </el-card>

      <!-- 公钥 -->
      <el-card class="result-card">
        <template #header>
          <div class="card-header">
            <span>🔑 公钥（Public Key）</span>
            <div>
              <el-button size="small" @click="copyText(result.publicKey, '公钥')">
                <el-icon><CopyDocument /></el-icon> 复制
              </el-button>
              <el-button size="small" type="primary" @click="download(result.publicKey, 'id_' + typeFilename + '.pub')">
                <el-icon><Download /></el-icon> 下载
              </el-button>
            </div>
          </div>
        </template>
        <el-alert type="info" :closable="false" style="margin-bottom:12px">
          将此内容添加到目标服务器的 <code>~/.ssh/authorized_keys</code> 即可启用免密登录。
        </el-alert>
        <el-input type="textarea" :model-value="result.publicKey" :rows="4" readonly class="mono-area" />
      </el-card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { generateRSA, generateECDSA, generateEd25519 } from '@/utils/ssh'
import type { SSHKeyPair } from '@/utils/ssh'

const form = ref({ type: 'Ed25519', comment: '', passphrase: '' })
const loading = ref(false)
const showPass = ref(false)
const result = ref<SSHKeyPair | null>(null)

const HINTS: Record<string, string> = {
  'RSA-2048': 'RSA 2048-bit 兼容性最好，支持所有 SSH 实现，适合需要与老系统兼容的场景。',
  'RSA-4096': 'RSA 4096-bit 安全性更高，生成约需 5–10 秒。若无特殊需求，建议用 Ed25519 代替。',
  'ECDSA-P256': 'ECDSA P-256 基于 NIST 椭圆曲线，密钥短、速度快，安全性等同 RSA 3072-bit。',
  'ECDSA-P384': 'ECDSA P-384 提供更高安全级别（192-bit security），适合对安全有更高要求的场景。',
  'ECDSA-P521': 'ECDSA P-521 最高安全级别椭圆曲线（260-bit security），适合长期密钥保护。',
  'Ed25519': 'Ed25519 是现代 SSH 首选：签名最快、密钥最短、安全性强（128-bit），OpenSSH 6.5+ 支持。',
}

const algoHint = computed(() => HINTS[form.value.type] || '')

const typeFilename = computed(() => {
  const map: Record<string, string> = {
    'RSA-2048': 'rsa', 'RSA-4096': 'rsa',
    'ECDSA-P256': 'ecdsa', 'ECDSA-P384': 'ecdsa', 'ECDSA-P521': 'ecdsa',
    'Ed25519': 'ed25519',
  }
  return map[form.value.type] || 'key'
})

// Password strength scoring
const strength = computed(() => {
  const p = form.value.passphrase
  if (!p) return { cls: '', pct: 0, label: '' }
  let score = 0
  if (p.length >= 8) score++
  if (p.length >= 16) score++
  if (p.length >= 24) score++
  if (/[A-Z]/.test(p)) score++
  if (/[a-z]/.test(p)) score++
  if (/[0-9]/.test(p)) score++
  if (/[^A-Za-z0-9]/.test(p)) score++
  if (score <= 2) return { cls: 'weak', pct: 25, label: '弱' }
  if (score <= 4) return { cls: 'medium', pct: 60, label: '中' }
  if (score <= 5) return { cls: 'good', pct: 80, label: '良' }
  return { cls: 'strong', pct: 100, label: '强' }
})

function onTypeChange() { result.value = null }
function onPassphraseChange() { result.value = null }

async function generate() {
  loading.value = true
  result.value = null
  const comment = form.value.comment.trim() || 'ssh-keytool'
  const passphrase = form.value.passphrase || undefined
  try {
    switch (form.value.type) {
      case 'RSA-2048':   result.value = await generateRSA(2048, comment, passphrase); break
      case 'RSA-4096':   result.value = await generateRSA(4096, comment, passphrase); break
      case 'ECDSA-P256': result.value = await generateECDSA('P-256', comment, passphrase); break
      case 'ECDSA-P384': result.value = await generateECDSA('P-384', comment, passphrase); break
      case 'ECDSA-P521': result.value = await generateECDSA('P-521', comment, passphrase); break
      case 'Ed25519':    result.value = await generateEd25519(comment, passphrase); break
    }
    ElMessage.success('密钥生成成功')
  } catch (e) {
    ElMessage.error('生成失败：' + String(e))
  } finally {
    loading.value = false
  }
}

async function copyText(text: string, label: string) {
  await navigator.clipboard.writeText(text)
  ElMessage.success(`${label}已复制`)
}

function download(content: string, filename: string) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([content], { type: 'text/plain' }))
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}
</script>

<style scoped>
.page { display: flex; flex-direction: column; gap: 20px; }
.page-header h2 { font-size: 22px; font-weight: 600; color: #1f2937; margin-bottom: 4px; }
.page-header p { color: #6b7280; font-size: 14px; }
.config-card, .result-card { border-radius: 12px; }

.passphrase-warn {
  display: flex; align-items: center; gap: 8px;
  margin-top: 8px; padding: 8px 12px; border-radius: 8px;
  background: #fff7ed; border: 1px solid #fed7aa;
  font-size: 13px; color: #c2410c;
}

.strength-wrap {
  display: flex; align-items: center; gap: 10px; margin-top: 8px;
}
.strength-bar {
  flex: 1; height: 6px; background: #e5e7eb; border-radius: 999px; overflow: hidden;
}
.strength-fill {
  height: 100%; border-radius: 999px; transition: width 0.3s, background 0.3s;
}
.strength-fill.weak   { background: #ef4444; }
.strength-fill.medium { background: #f59e0b; }
.strength-fill.good   { background: #3b82f6; }
.strength-fill.strong { background: #22c55e; }
.strength-label { font-size: 12px; font-weight: 600; width: 24px; }
.strength-label.weak   { color: #ef4444; }
.strength-label.medium { color: #f59e0b; }
.strength-label.good   { color: #3b82f6; }
.strength-label.strong { color: #22c55e; }

.algo-hint {
  display: flex; align-items: flex-start; gap: 8px;
  background: #f0f9ff; border: 1px solid #bae6fd;
  border-radius: 8px; padding: 10px 14px;
  font-size: 13px; color: #0369a1; margin-bottom: 16px;
}

.card-header { display: flex; justify-content: space-between; align-items: center; }
.card-header span { font-weight: 600; }
.info-item { background: #f9fafb; border-radius: 8px; padding: 12px 16px; }
.info-label { font-size: 12px; color: #6b7280; margin-bottom: 4px; }
.info-value { font-size: 14px; font-weight: 500; color: #111827; word-break: break-all; }
.info-value.mono { font-family: ui-monospace, monospace; font-size: 12px; }
.info-value.encrypted { color: #16a34a; }
.info-value.plain     { color: #dc2626; }

.mono-area :deep(.el-textarea__inner) {
  font-family: ui-monospace, 'JetBrains Mono', Consolas, monospace;
  font-size: 12px; line-height: 1.6; background: #1e1e2e; color: #cdd6f4; border-radius: 8px;
}
code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
</style>
