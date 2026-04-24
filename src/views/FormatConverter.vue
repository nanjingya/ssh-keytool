<template>
  <div class="page">
    <div class="page-header">
      <h2>格式转换</h2>
      <p>在 OpenSSH 公钥格式与 PEM（SPKI）格式之间互转</p>
    </div>

    <el-card>
      <el-form label-position="top">
        <el-form-item label="转换方向">
          <el-radio-group v-model="direction" @change="reset">
            <el-radio-button value="ssh2pem">SSH 公钥 → PEM（SPKI）</el-radio-button>
            <el-radio-button value="pem2ssh">PEM（SPKI）→ SSH 公钥</el-radio-button>
          </el-radio-group>
          <div style="font-size:12px;color:#6b7280;margin-top:6px">
            支持 RSA、ECDSA P-256/P-384/P-521、Ed25519
          </div>
        </el-form-item>

        <el-form-item :label="inputLabel">
          <el-input
            v-model="input"
            type="textarea"
            :rows="7"
            :placeholder="inputPlaceholder"
            class="mono-area"
          />
        </el-form-item>

        <div style="display: flex; gap: 12px">
          <el-button type="primary" :loading="loading" @click="convert" style="flex: 1">
            <el-icon><Switch /></el-icon> 转换
          </el-button>
          <el-button @click="reset">清空</el-button>
        </div>
      </el-form>
    </el-card>

    <el-card v-if="output">
      <template #header>
        <div class="card-header">
          <span>{{ outputLabel }}</span>
          <el-button size="small" @click="copyText(output)">
            <el-icon><CopyDocument /></el-icon> 复制
          </el-button>
        </div>
      </template>
      <el-input type="textarea" :model-value="output" :rows="8" readonly class="mono-area" />
    </el-card>

    <el-alert v-if="error" type="error" :title="error" :closable="false" show-icon />

    <el-card>
      <template #header><span style="font-weight: 600">格式说明</span></template>
      <el-table :data="formatTable" stripe>
        <el-table-column prop="format" label="格式" width="160" />
        <el-table-column prop="header" label="文件头" />
        <el-table-column prop="usage" label="用途" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { pemToOpenSSHPublic, opensshPublicToPem } from '@/utils/ssh'

const direction = ref<'ssh2pem' | 'pem2ssh'>('ssh2pem')
const input = ref('')
const output = ref('')
const loading = ref(false)
const error = ref('')

const inputLabel = computed(() =>
  direction.value === 'ssh2pem' ? 'SSH 公钥（authorized_keys 格式）' : 'PEM 公钥（SPKI 格式）'
)
const outputLabel = computed(() =>
  direction.value === 'ssh2pem' ? '转换结果：PEM（SPKI）格式' : '转换结果：SSH 公钥格式'
)
const inputPlaceholder = computed(() =>
  direction.value === 'ssh2pem'
    ? 'ssh-rsa AAAA... comment'
    : '-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----'
)

const formatTable = [
  { format: 'OpenSSH 公钥', header: 'ssh-rsa / ssh-ed25519 ...', usage: '用于 authorized_keys，SSH 认证' },
  { format: 'PEM SPKI', header: '-----BEGIN PUBLIC KEY-----', usage: 'TLS/SSL，Java/Go/Python 等程序读取' },
  { format: 'PEM PKCS#1', header: '-----BEGIN RSA PUBLIC KEY-----', usage: 'OpenSSL 传统格式（RSA 专用）' },
]

function reset() {
  input.value = ''
  output.value = ''
  error.value = ''
}

async function convert() {
  const raw = input.value.trim()
  if (!raw) { ElMessage.warning('请输入内容'); return }
  loading.value = true
  error.value = ''
  output.value = ''
  try {
    if (direction.value === 'ssh2pem') {
      output.value = await opensshPublicToPem(raw)
    } else {
      output.value = await pemToOpenSSHPublic(raw)
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
.card-header { display: flex; justify-content: space-between; align-items: center; font-weight: 600; }
.mono-area :deep(.el-textarea__inner) {
  font-family: ui-monospace, Consolas, monospace;
  font-size: 12px; background: #1e1e2e; color: #cdd6f4; border-radius: 8px;
}
</style>
