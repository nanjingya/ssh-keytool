<template>
  <div class="page">
    <div class="page-header">
      <h2>提取公钥</h2>
      <p>从 SSH 私钥中提取对应的公钥，支持 OpenSSH 格式和 RSA PEM 格式</p>
    </div>

    <el-alert type="info" :closable="false" show-icon style="border-radius: 10px">
      所有运算在浏览器本地完成，私钥内容不会上传到任何服务器。
    </el-alert>

    <el-card>
      <el-form label-position="top">
        <el-form-item label="SSH 私钥">
          <el-input
            v-model="input"
            type="textarea"
            :rows="12"
            placeholder="粘贴 SSH 私钥内容，支持：&#10;· OpenSSH 格式（-----BEGIN OPENSSH PRIVATE KEY-----）&#10;· RSA PEM 格式（-----BEGIN RSA PRIVATE KEY-----）&#10;· PKCS8 格式（-----BEGIN PRIVATE KEY-----）"
            class="mono-area"
          />
        </el-form-item>

        <el-form-item label="公钥注释（Comment，可选）">
          <el-input v-model="comment" placeholder="user@hostname 或自定义标识" />
        </el-form-item>

        <div style="display: flex; gap: 12px">
          <el-button type="primary" :loading="loading" @click="extract" style="flex: 1">
            <el-icon><Upload /></el-icon> 提取公钥
          </el-button>
          <el-button @click="reset">清空</el-button>
        </div>
      </el-form>
    </el-card>

    <el-card v-if="result">
      <template #header>
        <div class="card-header">
          <span>提取结果</span>
          <el-button size="small" @click="copyText(result)">
            <el-icon><CopyDocument /></el-icon> 复制
          </el-button>
        </div>
      </template>

      <el-alert type="success" :closable="false" style="margin-bottom: 12px">
        公钥提取成功！可直接将以下内容添加到服务器的 <code>~/.ssh/authorized_keys</code> 文件。
      </el-alert>

      <el-input type="textarea" :model-value="result" :rows="4" readonly class="mono-area" />

      <el-divider />

      <div v-if="fingerprint" class="fp-block">
        <div class="fp-row">
          <span class="fp-label">SHA256</span>
          <span class="fp-value mono">{{ fingerprint.sha256 }}</span>
        </div>
        <div class="fp-row">
          <span class="fp-label">MD5</span>
          <span class="fp-value mono">{{ fingerprint.md5 }}</span>
        </div>
      </div>
    </el-card>

    <el-alert v-if="error" type="error" :title="error" :closable="false" show-icon />

    <el-card>
      <template #header><span style="font-weight: 600">常见使用场景</span></template>
      <div class="scenario-list">
        <div class="scenario-item" v-for="s in scenarios" :key="s.title">
          <div class="s-icon">{{ s.icon }}</div>
          <div>
            <div class="s-title">{{ s.title }}</div>
            <div class="s-desc">{{ s.desc }}</div>
          </div>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'

const input = ref('')
const comment = ref('')
const loading = ref(false)
const result = ref('')
const fingerprint = ref<{ sha256: string; md5: string } | null>(null)
const error = ref('')

const scenarios = [
  { icon: '🔑', title: '私钥文件丢失公钥', desc: '只剩私钥，需要恢复对应的 authorized_keys 内容时使用' },
  { icon: '🖥️', title: '配置新服务器', desc: '有私钥文件但忘记公钥内容，需要添加到新服务器时' },
  { icon: '🔍', title: '验证密钥对匹配', desc: '确认某个私钥与服务器上的公钥是否对应' },
  { icon: '📋', title: '格式转换', desc: '将私钥中的公钥提取并转换为 authorized_keys 标准格式' },
]

async function extract() {
  const raw = input.value.trim()
  if (!raw) { ElMessage.warning('请输入私钥'); return }
  loading.value = true
  error.value = ''
  result.value = ''
  fingerprint.value = null
  try {
    const { extractPublicKey, parsePublicKey } = await import('@/utils/ssh')
    const pubKey = await extractPublicKey(raw, comment.value.trim() || 'extracted-key')
    result.value = pubKey
    const parsed = await parsePublicKey(pubKey)
    fingerprint.value = parsed.fingerprint
    ElMessage.success('公钥提取成功')
  } catch (e) {
    error.value = String(e)
  } finally {
    loading.value = false
  }
}

function reset() {
  input.value = ''
  comment.value = ''
  result.value = ''
  fingerprint.value = null
  error.value = ''
}

async function copyText(text: string) {
  await navigator.clipboard.writeText(text)
  ElMessage.success('已复制到剪贴板')
}
</script>

<style scoped>
.page { display: flex; flex-direction: column; gap: 20px; }
.page-header h2 { font-size: 22px; font-weight: 600; color: #1f2937; margin-bottom: 4px; }
.page-header p { color: #6b7280; font-size: 14px; }
.card-header { display: flex; justify-content: space-between; align-items: center; font-weight: 600; }
.mono-area :deep(.el-textarea__inner) {
  font-family: ui-monospace, Consolas, monospace;
  font-size: 12px; background: #1e1e2e; color: #cdd6f4; border-radius: 8px;
}
.fp-block { display: flex; flex-direction: column; gap: 10px; }
.fp-row { display: flex; align-items: center; gap: 12px; background: #f9fafb; padding: 10px 14px; border-radius: 8px; }
.fp-label { font-size: 12px; font-weight: 600; color: #6b7280; width: 56px; flex-shrink: 0; }
.fp-value { font-size: 13px; color: #111827; word-break: break-all; }
.scenario-list { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.scenario-item { display: flex; gap: 12px; align-items: flex-start; background: #f9fafb; border-radius: 10px; padding: 14px; }
.s-icon { font-size: 22px; flex-shrink: 0; }
.s-title { font-weight: 600; font-size: 14px; color: #111827; margin-bottom: 4px; }
.s-desc { font-size: 13px; color: #6b7280; line-height: 1.5; }
code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 12px; font-family: monospace; }
@media (max-width: 640px) {
  .scenario-list { grid-template-columns: 1fr; }
}
</style>
