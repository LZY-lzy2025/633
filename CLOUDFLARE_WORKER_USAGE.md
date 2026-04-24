# Cloudflare Worker 解密脚本说明

这个仓库里的 `4.txt` 之类内容是：

1. Base64 字符串
2. 用 **AES-128-ECB + PKCS7** 加密
3. key 由以下 16 个字节拼出来（与 `decrypt_live_record.js` 一致）

```txt
KVksL2jJ6eLOP7cX
```

## 为什么你之前会“部署不了”

你截图里的报错：

```txt
No such module "crypto-js"
```

是因为 Cloudflare 控制台在线编辑器不会自动帮你安装 npm 包。

现在新版 `cloudflare_worker_decrypt.js` **已移除 `crypto-js` 依赖**，改为纯 JavaScript 内置实现 AES-128-ECB，可直接在 Cloudflare 控制台粘贴部署。

## 你要的场景

你会提供一个接口，接口返回内容类似 `4.txt`（即加密后的 Base64 字符串）。

`cloudflare_worker_decrypt.js` 会：

- 请求你的接口
- 读取接口返回中的加密字符串（支持纯文本，或 JSON 中的 `data/payload/encrypted/ciphertext/content` 字段）
- 解密后返回 JSON

## 在 Cloudflare Workers 运行

### 方式 A：Cloudflare 控制台直接粘贴（推荐）

1. 创建 Worker。
2. 把 `cloudflare_worker_decrypt.js` 全量粘贴到 `worker.js`。
3. 设置环境变量 `ENCRYPTED_API_URL`（可选）。
4. 保存并部署。

### 方式 B：Wrangler

1. 初始化 Worker（如果你还没有项目）：

```bash
npm create cloudflare@latest
```

2. 把 `cloudflare_worker_decrypt.js` 复制到 Worker 项目 `src/worker.js`（或你的入口文件）。

3. 配置环境变量（可选）：

```toml
# wrangler.toml
[vars]
ENCRYPTED_API_URL = "https://your-api.example.com/encrypted"
```

4. 本地调试：

```bash
npx wrangler dev
```

## 调用方式

- 如果配置了 `ENCRYPTED_API_URL`：
  - 直接请求 Worker：`GET /`
- 如果想临时指定接口：
  - `GET /?url=https://your-api.example.com/encrypted`

Worker 返回示例：

```json
{
  "keyUtf8": "KVksL2jJ6eLOP7cX",
  "sourceUrl": "https://your-api.example.com/encrypted",
  "decrypted": {
    "code": "200",
    "msg": "成功",
    "data": {}
  }
}
```
