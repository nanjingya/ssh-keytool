import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
  { path: '/', redirect: '/generate' },
  {
    path: '/generate',
    component: () => import('@/views/KeyGenerator.vue'),
    meta: { title: '密钥生成', icon: 'Key' },
  },
  {
    path: '/inspect',
    component: () => import('@/views/KeyInspector.vue'),
    meta: { title: '密钥解析', icon: 'Search' },
  },
  {
    path: '/fingerprint',
    component: () => import('@/views/FingerprintCalc.vue'),
    meta: { title: '指纹计算', icon: 'Finished' },
  },
  {
    path: '/convert',
    component: () => import('@/views/FormatConverter.vue'),
    meta: { title: '格式转换', icon: 'Switch' },
  },
  {
    path: '/extract',
    component: () => import('@/views/PublicKeyExtract.vue'),
    meta: { title: '提取公钥', icon: 'Upload' },
  },
]

export default createRouter({
  history: createWebHashHistory(),
  routes,
})
