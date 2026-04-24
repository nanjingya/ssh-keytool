<template>
  <div class="page">
    <div class="page-header">
      <h2>SSH 密钥解析</h2>
      <p>粘贴任意 SSH 公钥，解析其类型、长度、指纹等详细信息</p>
    </div>

    <el-card>
      <el-form label-position="top">
        <el-form-item label="SSH 公钥">
          <el-input
            v-model="input"
            type="textarea"
            :rows="5"
            placeholder="粘贴 SSH 公钥，例如：&#10;ssh-rsa AAAA...&#10;ssh-ed25519 AAAA...&#10;ecdsa-sha2-nistp256 AAAA..."
            class="mono-area"
          />
        </el-form-item>
        <div style="display: flex; gap: 12px">
          <el-button type="primary" :loading="loading" @click="inspect" style="flex: 1">
            <el-icon><Search /></el-icon> 解析密钥
          </el-button>
          <el-button @click="reset">清空</el-button>
        </div>
      </el-form>
    </el-card>

    <el-card v-if="result">
      <template #header>
        <div class="card-header">
          <span>解析结果</span>
          <el-tag :type="tagType">{{ result.type }}</el-tag>
        </div>
      </template>

      <el-descriptions :column="2" border>
        <el-descriptions-item label="密钥类型">
          <span class="mono">{{ result.type }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="注释（Comment）">
          {{ result.comment || '（无）' }}
        </el-descriptions-item>
        <template v-for="(val, key) in result.details" :key="key">
          <el-descriptions-item :label="String(key)">
            <span :class="{ mono: isMonoField(String(key)) }">{{ val }}</span>
          </el-descriptions-item>
        </template>
        <el-descriptions-item label="Blob 长度">
          {{ result.blob.length }} bytes
        </el-descriptions-item>
      </el-descriptions>

      <el-divider>指纹（Fingerprint）</el-divider>

      <div class="fingerprint-block">
        <div class="fp-row">
          <span class="fp-label">SHA256</span>
          <span class="fp-value mono">{{ result.fingerprint.sha256 }}</span>
          <el-button size="small" link @click="copyText(result.fingerprint.sha256)">
            <el-icon><CopyDocument /></el-icon>
          </el-button>
        </div>
        <div class="fp-row">
          <span class="fp-label">MD5</span>
          <span class="fp-value mono">{{ result.fingerprint.md5 }}</span>
          <el-button size="small" link @click="copyText(result.fingerprint.md5)">
            <el-icon><CopyDocument /></el-icon>
          </el-button>
        </div>
      </div>

      <el-divider>原始 Base64 Blob</el-divider>
      <el-input
        type="textarea"
        :model-value="base64Blob"
        :rows="3"
        readonly
        class="mono-area"
      />
    </el-card>

    <el-alert v-if="error" type="error" :title="error" :closable="false" show-icon />
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import type { ParsedPublicKey } from '@/utils/ssh'

const input = ref('')
const loading = ref(false)
const result = ref<ParsedPublicKey | null>(null)
const error = ref('')

const tagType = computed(() => {
  if (!result.value) return 'info'
  if (result.value.type === 'ssh-ed25519') return 'success'
  if (result.value.type.startsWith('ecdsa')) return 'warning'
  return 'info'
})

const base64Blob = computed(() =>
  result.value ? btoa(String.fromCharCode(...result.value.blob)) : ''
)

function isMonoField(key: string): boolean {
  return ['公钥', '公钥指数 (e)'].includes(key)
}

async function inspect() {
  if (!input.value.trim()) {
    ElMessage.warning('请先输入 SSH 公钥')
    return
  }
  loading.value = true
  error.value = ''
  result.value = null
  try {
    const { parsePublicKey } = await import('@/utils/ssh')
    result.value = await parsePublicKey(input.value.trim())
  } catch (e) {
    error.value = String(e)
  } finally {
    loading.value = false
  }
}

function reset() {
  input.value = ''
  result.value = null
  error.value = ''
}

async function copyText(text: string) {
  await navigator.clipboard.writeText(text)
  ElMessage.success('已复制')
}
</script>

<style scoped>
.page { display: flex; flex-direction: column; gap: 20px; }
.page-header h2 { font-size: 22px; font-weight: 600; color: #1f2937; margin-bottom: 4px; }
.page-header p { color: #6b7280; font-size: 14px; }
.card-header { display: flex; justify-content: space-between; align-items: center; font-weight: 600; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 13px; }
.fingerprint-block { display: flex; flex-direction: column; gap: 12px; }
.fp-row { display: flex; align-items: center; gap: 12px; background: #f9fafb; padding: 12px 16px; border-radius: 8px; }
.fp-label { font-size: 12px; font-weight: 600; color: #6b7280; width: 56px; flex-shrink: 0; }
.fp-value { flex: 1; font-size: 13px; color: #111827; word-break: break-all; }
.mono-area :deep(.el-textarea__inner) {
  font-family: ui-monospace, Consolas, monospace;
  font-size: 12px; background: #1e1e2e; color: #cdd6f4; border-radius: 8px;
}
</style>
