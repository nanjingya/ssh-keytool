<template>
  <div class="page">
    <div class="page-header">
      <h2>SSH 指纹计算</h2>
      <p>计算 SSH 公钥的 SHA256 和 MD5 指纹，用于服务器身份验证确认</p>
    </div>

    <el-card>
      <el-form label-position="top">
        <el-form-item label="SSH 公钥或公钥 Base64 Blob">
          <el-input
            v-model="input"
            type="textarea"
            :rows="5"
            placeholder="支持以下格式：&#10;1. SSH 公钥：ssh-rsa AAAA... comment&#10;2. 纯 Base64 blob（公钥中间部分）"
            class="mono-area"
          />
        </el-form-item>
        <el-button type="primary" :loading="loading" @click="calc" style="width: 100%">
          <el-icon><Finished /></el-icon> 计算指纹
        </el-button>
      </el-form>
    </el-card>

    <el-card v-if="result">
      <template #header><span style="font-weight: 600">指纹结果</span></template>

      <div class="fp-list">
        <div class="fp-item">
          <div class="fp-header">
            <span class="fp-algo">SHA256</span>
            <span class="fp-badge">推荐</span>
          </div>
          <div class="fp-value mono">{{ result.sha256 }}</div>
          <el-button size="small" @click="copyText(result.sha256)" style="margin-top: 8px">
            <el-icon><CopyDocument /></el-icon> 复制
          </el-button>
        </div>

        <div class="fp-item">
          <div class="fp-header">
            <span class="fp-algo">MD5</span>
            <span class="fp-badge legacy">旧版兼容</span>
          </div>
          <div class="fp-value mono">{{ result.md5 }}</div>
          <el-button size="small" @click="copyText(result.md5)" style="margin-top: 8px">
            <el-icon><CopyDocument /></el-icon> 复制
          </el-button>
        </div>
      </div>

      <el-divider />

      <el-collapse>
        <el-collapse-item title="什么是 SSH 指纹？">
          <div class="help-text">
            <p>SSH 指纹（Fingerprint）是对公钥 Blob 进行哈希计算后得到的摘要，用于唯一标识一个 SSH 密钥。</p>
            <p style="margin-top: 8px">当你第一次 SSH 连接到服务器时，系统会显示服务器公钥的指纹让你确认，防止中间人攻击（MITM）。</p>
            <p style="margin-top: 8px"><strong>SHA256 格式</strong>（现代 OpenSSH 默认）：<code>SHA256:xxxxx...</code></p>
            <p style="margin-top: 4px"><strong>MD5 格式</strong>（旧版兼容）：<code>xx:xx:xx:xx:...</code></p>
          </div>
        </el-collapse-item>
        <el-collapse-item title="如何验证服务器指纹？">
          <div class="help-text">
            <p>运行以下命令获取服务器主机密钥指纹：</p>
            <pre class="code-block">ssh-keyscan -t ed25519 your-server.com | ssh-keygen -lf -</pre>
            <p style="margin-top: 8px">将输出的指纹与本工具计算结果对比，一致则表示连接安全。</p>
          </div>
        </el-collapse-item>
      </el-collapse>
    </el-card>

    <el-alert v-if="error" type="error" :title="error" :closable="false" show-icon />
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'

const input = ref('')
const loading = ref(false)
const result = ref<{ sha256: string; md5: string } | null>(null)
const error = ref('')

async function calc() {
  const raw = input.value.trim()
  if (!raw) { ElMessage.warning('请输入公钥'); return }
  loading.value = true
  error.value = ''
  result.value = null
  try {
    const { parsePublicKey, fingerprintFromBase64Blob } = await import('@/utils/ssh')
    if (raw.includes(' ')) {
      const parsed = await parsePublicKey(raw)
      result.value = parsed.fingerprint
    } else {
      result.value = await fingerprintFromBase64Blob(raw)
    }
  } catch (e) {
    error.value = String(e)
  } finally {
    loading.value = false
  }
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
.fp-list { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.fp-item { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; }
.fp-header { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.fp-algo { font-size: 16px; font-weight: 700; color: #111827; }
.fp-badge { background: #dcfce7; color: #16a34a; font-size: 11px; padding: 2px 8px; border-radius: 999px; font-weight: 600; }
.fp-badge.legacy { background: #fef9c3; color: #a16207; }
.fp-value { font-family: ui-monospace, Consolas, monospace; font-size: 13px; color: #374151; word-break: break-all; line-height: 1.6; }
.help-text { font-size: 14px; color: #4b5563; line-height: 1.7; }
.code-block { background: #1e1e2e; color: #cdd6f4; padding: 10px 14px; border-radius: 8px; font-family: ui-monospace, monospace; font-size: 13px; margin-top: 8px; overflow-x: auto; }
code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 12px; font-family: monospace; }
.mono-area :deep(.el-textarea__inner) {
  font-family: ui-monospace, Consolas, monospace;
  font-size: 12px; background: #1e1e2e; color: #cdd6f4; border-radius: 8px;
}
@media (max-width: 640px) {
  .fp-list { grid-template-columns: 1fr; }
}
</style>
