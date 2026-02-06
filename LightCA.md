我想构建一个基于 Docker + Python 的 Web CA 证书、密钥管理和签发平台,项目名称叫LightCA。

## 主要功能

### 1. CA 证书管理

- **根 CA 创建**：生成自签名的根证书颁发机构,可选设置私钥密码,可选记住私钥密码
- **中间 CA 创建**：基于现有 CA 创建下级 CA,支持多级 CA 层级
- **CA 导入**：导入外部 PEM/DER 格式的 CA 证书和私钥,可选记住私钥密码
- **CA 吊销**：吊销 CA 证书并更新吊销列表
- **CA 导出**：导出 CA 证书（含私钥可选）
- **CA 链查看**：获取完整的 CA 证书链

### 2. 终端证书管理

- **证书签发**：基于模板或自定义配置签发 X.509 证书
- **CSR 签署**：接收并签署证书签名请求（CSR）
- **证书导入**：导入外部 PEM/DER 格式的证书和私钥
- **证书吊销**：吊销证书并记录吊销原因
- **证书导出**：支持多种格式导出（PEM、DER、PKCS#12）
- **证书链**：获取完整的证书信任链

### 3. 密钥管理

- **密钥生成**：支持 RSA（2048/4096）、ECDSA（P-256/P-384）、EdDSA（Ed25519/Ed448）算法
- **密钥导入**：导入加密或未加密的 PEM 格式私钥
- **密钥加密**：使用 AES-256-GCM 加密存储私钥（MASTER_KEY）
- **记住密钥密码**：使用 AES-256-GCM 加密存储私钥密码，签发证书时自动调用（MASTER_KEY）
- **密钥导出**：导出加密格式的私钥

### 4. 证书模板管理

- **内置模板**：提供常用的证书模板（服务器证书、客户端证书、Email证书、代码签名证书、openvpn证书等）
- **自定义模板**：创建和管理自定义证书模板
- **模板配置**：配置密钥算法、有效期、Key Usage、Extended Key Usage、SAN 等扩展

### 5. CRL（证书吊销列表）管理

- **CRL 生成**：为指定 CA 生成 CRL
- **CRL 下载**：公开端点下载 CRL 文件
- **吊销记录查询**：查看指定 CA 的所有吊销记录

### 6. 统计与监控

- **证书统计**：CA 数量、终端证书数量
- **过期监控**：即将过期证书统计（30天内）
- **吊销统计**：已吊销证书数量

## 技术方案

### 技术栈

- **后端**: FastAPI + Uvicorn + SQLAlchemy + RPC风格API + cryptography
- **数据库**: SQLite（默认,支持加密）或 PostgreSQL（可选）
- **证书处理**: cryptography 库
- **前端**: 现代化的WEBUI后台管理界面,界面精美
- **部署**: Docker + docker-compose + Github Action 自动编译至ghcr.io

### 数据库设计

| 表名           | 说明         | 关键字段                                                                                                                                                                                                                                                    |
| -------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `certificates` | X.509 证书   | id, type(root, intermediate, leaf), parent_id, key_id(为了兼容导入CSR的情形，可为空), serial_number, subject_cn, not_after, status(valid, revoked, expired), certificate_der, meta_data(存 Subject DN, SANs, Extensions 等所有详情), revoked_at, is_deleted |
| `keys`         | 私钥         | id, algorithm, fingerprint, encrypted_pem, is_protected, encrypted_password, meta_data, is_deleted                                                                                                                                                          |
| `templates`    | 证书模板     | id, name, template_type, key_usage(算法与长度等配置), extended_key_usage(KU, EKU, SAN 等扩展), policy(是否允许覆盖特定字段)                                                                                                                                 |
| `crls`         | 证书吊销列表 | id, ca_id, crl_number, crl_der, generated_at                                                                                                                                                                                                                |

其中certificates、keys表的meta_data以及templates表的key_usage、extended_key_usage、policy使用json储存

### 安全机制

1. **认证与授权**
   - 基于 JWT Bearer Token 的认证, MASTER_KEY（环境变量,最少 32 字符）
   - 单一管理员账户（admin）,密码通过环境变量配置，密码支持在环境变量中配置明文和Bcrypt Hash
   - Token 有效期：1440 分钟（24 小时）
   - Token通过header传递

2. **私钥保护**

- 私钥pem内容加密储存（使用 MASTER_KEY 加密）
- 私钥可选记住密码（可记住密码,使用 MASTER_KEY 加密）
- 私钥密码加密使用 MASTER_KEY（环境变量,最少 32 字符）

3. **证书安全**
   - 支持密钥长度限制（RSA 2048/4096）
   - 支持安全的椭圆曲线（P-256, P-384）
   - 支持安全的 EdDSA 算法（Ed25519, Ed448）

### 加密算法支持

| 类型      | 算法           | 密钥长度/曲线   |
| --------- | -------------- | --------------- |
| **RSA**   | RSA            | 2048, 4096 bits |
| **ECDSA** | ECDSA          | P-256, P-384    |
| **EdDSA** | Ed25519, Ed448 | 256, 448 bits   |

### 证书扩展支持

- **Basic Constraints**：CA 标记、路径长度约束
- **Key Usage**：数字签名、密钥加密、证书签名等
- **Extended Key Usage**：服务器认证、客户端认证、代码签名等
- **Subject Alternative Name (SAN)**：DNS、IP 地址、Email、URI

### 证书导出格式

| 格式           | 说明                                 |
| -------------- | ------------------------------------ |
| **PEM**        | 标准 PEM 格式证书                    |
| **PEM Chain**  | 完整证书链（PEM 格式）               |
| **PEM Bundle** | 完整证书链 + 证书 + 私钥（PEM 格式） |
| **DER**        | DER 二进制格式                       |
| **PKCS#12**    | .p12 文件,包含证书和私钥             |

## 后端 API 清单

### 认证模块 (`/api/auth`)

| 方法 | 端点              | 说明                    | 认证 |
| ---- | ----------------- | ----------------------- | ---- |
| POST | `/api/auth/login` | 用户登录,返回 JWT token | 否   |

### 证书管理模块 (`/api/certificates`)

| 方法 | 端点                       | 说明                                                                                                            | 认证 |
| ---- | -------------------------- | --------------------------------------------------------------------------------------------------------------- | ---- |
| GET  | `/api/certificates/list`   | 获取证书列表（分页、筛选type、parent_id、search）                                                               | 是   |
| POST | `/api/certificates/sign`   | 统一证书创建和签发接口（issuer_id、is_ca、subject、key_config、validity_days、extensions、csr_pem(可选)等内容） | 是   |
| POST | `/api/certificates/import` | 导入证书/CA，导入证书。后端自动分析是 CA 还是 Leaf 并设置 type                                                  | 是   |
| GET  | `/api/certificates/detail` | 获取证书详情（包含解析后的 JSON 元数据）                                                                        | 是   |
| POST | `/api/certificates/delete` | 删除证书（同时删除私钥）                                                                                        | 是   |
| POST | `/api/certificates/revoke` | 吊销证书                                                                                                        | 是   |
| GET  | `/api/certificates/export` | 导出证书与私钥（多种格式，password 参数可选：留空则导出明文私钥，填写则对导出文件进行加密                       | 是   |
| GET  | `/api/certificates/chain`  | 获取完整的证书链（递归向上查找）                                                                                | 是   |
| GET  | `/api/certificates/tree`   | 层级树结构,返回嵌套 JSON,用于前端展示 CA 拓扑图。                                                               | 是   |

### 证书密钥管理模块 (`/api/keys`)

| 方法 | 端点               | 说明                                                                      | 认证 |
| ---- | ------------------ | ------------------------------------------------------------------------- | ---- |
| GET  | `/api/keys/list`   | 获取密钥列表（分页、筛选）                                                | 是   |
| POST | `/api/keys/create` | 生成新密钥                                                                | 是   |
| POST | `/api/keys/import` | 导入私钥                                                                  | 是   |
| GET  | `/api/keys/detail` | 获取密钥详情                                                              | 是   |
| POST | `/api/keys/delete` | 删除密钥                                                                  | 是   |
| GET  | `/api/keys/export` | 导出私钥，password 参数可选：留空则导出明文私钥，填写则对导出文件进行加密 | 是   |

### 模板管理模块 (`/api/templates`)

| 方法 | 端点                    | 说明                       | 认证 |
| ---- | ----------------------- | -------------------------- | ---- |
| GET  | `/api/templates/list`   | 获取模板列表（分页、筛选） | 是   |
| POST | `/api/templates/create` | 创建模板                   | 是   |
| GET  | `/api/templates/detail` | 获取模板详情               | 是   |
| POST | `/api/templates/update` | 更新模板                   | 是   |
| POST | `/api/templates/delete` | 删除模板                   | 是   |

### CRL 管理模块 (`/api/crl`)

| 方法 | 端点                   | 说明             | 认证 |
| ---- | ---------------------- | ---------------- | ---- |
| GET  | `/api/crl/list`        | 获取 CRL 列表    | 是   |
| POST | `/api/crl/generate`    | 生成 CRL         | 是   |
| GET  | `/api/crl/download`    | 下载 CRL         | 是   |
| GET  | `/api/crl/revocations` | 获取吊销记录列表 | 是   |

### 统计模块 (`/api/stats`)

| 方法 | 端点         | 说明             | 认证 |
| ---- | ------------ | ---------------- | ---- |
| GET  | `/api/stats` | 获取系统统计信息 | 是   |

### 公开端点 (`/public`)（无需认证）

| 方法 | 端点                      | 说明             |
| ---- | ------------------------- | ---------------- |
| GET  | `/public/health`          | 健康检查         |
| GET  | `/public/crl/{ca_id}.crl` | 公开 CRL 下载    |
| GET  | `/public/ca/{ca_id}.crt`  | 公开 CA 证书下载 |

---

## 环境配置

### 必需配置项

```bash
# 主密钥（用于 JWT 签名和私钥、私钥密码加密）,最少 32 字符
MASTER_KEY=your-secret-master-key-min-32-chars-long

# 管理员密码
ADMIN_PASSWORD=your-admin-password
```

### 可选配置项

```bash
# 数据库配置
DB_TYPE=sqlite  # 或 postgresql
DATABASE_URL=postgresql://user:pass@host/db

# JWT 配置
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=1440  # 24 小时

# CRL 配置
CRL_DISTRIBUTION_URL=http://example.com/public/crl
CRL_VALIDITY_DAYS=7

# 服务器配置
HOST=0.0.0.0
PORT=8000
DEBUG=false
LOG_LEVEL=info
```

---

## 5. 前端设计方案 (DaisyUI)

采用 **SSR (Jinja2)** + **Utility CSS (DaisyUI)** 模式，无需 Node.js 构建流程。

### 5.1 布局与风格

- **组件库**: Tailwind CSS (CDN) + DaisyUI (CDN)。
- **布局**: 使用 DaisyUI `Drawer` 组件。左侧为导航菜单，右侧为内容区。
- **主题**: 支持 `light` (Winter) / `dark` (Dim) 切换。

### 5.2 状态视觉规范 (DaisyUI Badge)

- 🟢 **Valid**: `<div class="badge badge-success badge-outline">Valid</div>`
- 🔴 **Revoked**: `<div class="badge badge-error gap-2"><i class="ph ph-prohibit"></i>Revoked</div>`
- 🟡 **Expiring**: `<div class="badge badge-warning">Expiring</div>`
- 🟣 **Root CA**: `<div class="badge badge-primary">Root CA</div>`

### 5.3 关键页面交互

1. **证书拓扑图**: 使用 DaisyUI Menu 组件 (<ul class="menu">) 结合 HTML5 <details>/<summary> 实现,Jinja2 必须定义一个 Recursive Macro (递归宏) 来渲染节点
2. **CA页面：列表页**: 卡片式布局，展示 CA 层级关系、CRL 状态，详情页: 侧重于“签发下级 CA”和“生成 CRL”。
3. **Certificates (Leaf)页面**:列表页: 表格布局 (DataTable)，支持按 CN/IP 搜索，按有效期排序。签发页: 重点展示 CSR 上传和模板选择。
4. **签发表单**:

- 使用 DaisyUI `Tabs (Boxed)` 切换 [CSR 模式] / [生成模式]。
- [生成模式] 下显示：算法选择 (`select`), CN 输入 (`input`), 有效期 (`range` slider).
- [CSR 模式] 下显示：文件上传 (`file-input`) 或 文本域 (`textarea`).
- 签发等耗时操作，按钮显示加载动画。

4. **复制体验**:

- Input Group 使用 DaisyUI `join` 组件：

```html
<div class="join w-full">
  <input
    class="input input-bordered join-item w-full font-mono"
    readonly
    value="..."
  />
  <button class="btn join-item" @click="...">Copy</button>
</div>
```
