# LightCA

基于 Docker + Python 的 Web CA 证书、密钥管理与签发平台。

## 概览

LightCA 是一个基于 FastAPI 的内部 PKI 工具，用于管理：

- 根证书 / 中间证书 / 终端证书（Leaf）
- 私钥（RSA / ECDSA / EdDSA）
- 证书模板
- CRL 与吊销记录
- CA 证书与 CRL 的公开下载接口

## 技术栈

- 后端：FastAPI、SQLAlchemy、Alembic、cryptography
- 前端：Jinja2 templates、Alpine.js、Tailwind + DaisyUI（CDN）
- 认证与加密：JWT + bcrypt + AES-256-GCM
- 运行方式：Docker / docker-compose 或本地 Python

## 快速开始

### Docker（推荐）

```bash
git clone <your-repo-url>
cd LightCA
cp .env.example .env
# 编辑 .env，设置 MASTER_KEY、ADMIN_PASSWORD
docker-compose up -d
```

访问地址：

- 前端：`http://localhost:8000`
- API 文档（当 `DEBUG=true` 时）：`http://localhost:8000/docs`
- 健康检查：`http://localhost:8000/public/health`

### 本地 Python

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# 编辑 .env
alembic upgrade head
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## 核心 API 分组

- `/api/auth` 登录
- `/api/keys` 密钥生命周期管理
- `/api/certificates` 签发 / 导入 / 导出 / 吊销 / 树 / 证书链
- `/api/templates` 模板 CRUD
- `/api/crl` CRL 生成 / 下载 / 吊销列表
- `/api/stats` 仪表盘统计
- `/public` 健康检查与公开下载

## 开发

在 `backend/` 目录下执行：

```bash
pytest -q
```

CI 工作流：`.github/workflows/build.yml`（在 push/PR 时运行后端测试）。

## 文档

- 产品规格 / 实现目标：`LightCA.md`
- 贡献指南：`CONTRIBUTING.md`
- 部署说明：`DEPLOYMENT.md`
