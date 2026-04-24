<template>
  <el-container class="layout">
    <!-- 侧边栏 -->
    <el-aside width="220px" class="sidebar">
      <div class="logo">
        <span class="logo-icon">🔐</span>
        <div>
          <div class="logo-title">SSH KeyTool</div>
          <div class="logo-sub">纯前端 · 本地运算</div>
        </div>
      </div>

      <el-menu
        :default-active="currentPath"
        router
        class="side-menu"
      >
        <el-menu-item v-for="r in navRoutes" :key="r.path" :index="r.path">
          <el-icon><component :is="r.meta.icon" /></el-icon>
          <span>{{ r.meta.title }}</span>
        </el-menu-item>
      </el-menu>

      <div class="sidebar-footer">
        <div class="privacy-badge">
          <el-icon><Lock /></el-icon>
          所有数据本地处理
        </div>
        <a href="https://github.com/nanjingya/ssh-keytool" target="_blank" class="github-link">
          <svg height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
          GitHub
        </a>
      </div>
    </el-aside>

    <!-- 主内容区 -->
    <el-main class="main-content">
      <div class="content-wrap">
        <router-view />
      </div>
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()
const currentPath = computed(() => route.path)

const navRoutes = [
  { path: '/generate', meta: { title: '密钥生成', icon: 'Key' } },
  { path: '/inspect', meta: { title: '密钥解析', icon: 'Search' } },
  { path: '/fingerprint', meta: { title: '指纹计算', icon: 'Finished' } },
  { path: '/convert', meta: { title: '格式转换', icon: 'Switch' } },
  { path: '/extract', meta: { title: '提取公钥', icon: 'Upload' } },
]
</script>

<style scoped>
.layout { height: 100vh; overflow: hidden; }

.sidebar {
  background: #1e1e2e;
  display: flex;
  flex-direction: column;
  border-right: 1px solid #313244;
  flex-shrink: 0;
}

.logo {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 20px 16px;
  border-bottom: 1px solid #313244;
}

.logo-icon { font-size: 28px; }
.logo-title { font-size: 15px; font-weight: 700; color: #cdd6f4; }
.logo-sub { font-size: 11px; color: #6c7086; margin-top: 2px; }

.side-menu {
  flex: 1;
  background: transparent;
  border-right: none;
  padding: 8px;
}

.side-menu :deep(.el-menu-item) {
  color: #a6adc8;
  border-radius: 8px;
  margin: 2px 0;
  height: 44px;
}

.side-menu :deep(.el-menu-item:hover) {
  background: #313244;
  color: #cdd6f4;
}

.side-menu :deep(.el-menu-item.is-active) {
  background: #89b4fa20;
  color: #89b4fa;
}

.sidebar-footer {
  padding: 16px;
  border-top: 1px solid #313244;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.privacy-badge {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #a6e3a1;
  background: #a6e3a115;
  padding: 6px 10px;
  border-radius: 6px;
}

.github-link {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #6c7086;
  text-decoration: none;
  padding: 6px 10px;
  border-radius: 6px;
  transition: color 0.2s;
}

.github-link:hover { color: #cdd6f4; }

.main-content {
  background: #f0f2f5;
  overflow-y: auto;
  padding: 0;
}

.content-wrap {
  max-width: 900px;
  margin: 0 auto;
  padding: 28px 24px;
}
</style>
