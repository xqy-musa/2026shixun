# 用户信息管理平台

基于 Python Flask 框架的简易用户信息管理系统，包含登录/登出、用户信息展示等基础功能。

---

## 📅 项目版本说明

### v1.0 — 初始版本

初始版本实现了基本的用户登录与信息展示功能，包含以下文件：

| 文件 | 功能 |
|------|------|
| `app.py` | Flask 主应用，含用户数据库和路由 |
| `templates/base.html` | 基础模板（导航栏） |
| `templates/index.html` | 首页（用户信息展示） |
| `templates/login.html` | 登录页 |
| `static/css/style.css` | 页面样式 |

初始版本存在 **7 项安全漏洞**（高危 4 项、中危 2 项、低危 1 项）：

| 编号 | 漏洞名称 | 等级 |
|------|----------|------|
| VUL-01 | 用户密码明文存储与明文校验 | 🔴 高危 |
| VUL-02 | 前端源代码注释泄露管理员账号 | 🔴 高危 |
| VUL-03 | 页面回显完整敏感用户信息（含密码） | 🔴 高危 |
| VUL-04 | 无 CSRF 跨站请求伪造防护 | 🔴 高危 |
| VUL-05 | 用户输入未过滤 — XSS 注入风险 | 🟡 中危 |
| VUL-06 | 服务端调试模式常开，报错泄露源码 | 🟡 中危 |
| VUL-07 | 固定弱密钥导致会话可伪造 | 🟢 低危 |

---

### v2.0 — 安全加固版本（2026-07-19）

2026 年 7 月 19 日对全部 7 项漏洞进行了系统性修复，并增加了额外的安全加固措施。

#### 漏洞修复对照

| 编号 | 修复措施 |
|------|----------|
| ✅ VUL-01 | 采用 `werkzeug.security` 的 `generate_password_hash()`（scrypt 算法）对密码进行不可逆哈希加密，登录时使用 `check_password_hash()` 安全比对 |
| ✅ VUL-02 | 删除 `login.html` 中的 HTML 调试注释，消除敏感信息泄露点 |
| ✅ VUL-03 | 新增 `sanitize_user_info()` 脱敏函数：移除 password 字段，手机号中间四位替换为 `****`，余额格式化为货币显示 |
| ✅ VUL-04 | 基于 `secrets` 模块实现 CSRF 令牌机制，通过 `@app.before_request` 全局拦截校验所有 POST 请求 |
| ✅ VUL-05 | 新增 `sanitize_input()` 过滤函数，移除 HTML 标签和 `javascript:` 伪协议；表单增加 `maxlength` 限制 |
| ✅ VUL-06 | 调试模式改为环境变量 `FLASK_DEBUG` 控制，默认关闭，避免生产环境源码泄露 |
| ✅ VUL-07 | 废弃硬编码密钥，优先读取环境变量 `SECRET_KEY`，否则自动生成 256 位随机密钥；设置 2 小时会话超时、HttpOnly、SameSite=Lax |

#### 额外加固

- **会话固定防护**：登录成功后调用 `session.clear()` 重置会话
- **CSRF 令牌随机化**：登录成功后会重新生成 CSRF token
- **@login_required 装饰器**：提供可复用的登录保护装饰器
- **密码永不传递到前端**：`sanitize_user_info()` 彻底排除 password 字段

---

## 🚀 快速启动

```bash
# 1. 克隆项目
git clone https://github.com/xqy-musa/2026shixun.git
cd 2026shixun

# 2. 安装依赖
pip install flask

# 3. 启动服务（默认生产模式，关闭调试）
python3 app.py
```

### 环境变量说明

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SECRET_KEY` | Flask 会话签名密钥 | 自动生成 256 位随机密钥 |
| `FLASK_DEBUG` | 是否开启调试模式 | `false`（关闭） |

---

## 👤 内置用户

| 用户名 | 密码 | 角色 | 邮箱 | 手机 |
|--------|------|------|------|------|
| admin | admin123 | admin | admin@example.com | 13800138000 |
| alice | alice2025 | user | alice@example.com | 13900139001 |

> 注：密码在系统中以 scrypt 哈希密文形式存储，原始密码仅在初始构建时出现。

---

## 🛠 技术栈

| 项目 | 说明 |
|------|------|
| 开发语言 | Python 3 |
| 开发框架 | Flask |
| 模板引擎 | Jinja2 |
| 前端技术 | HTML5 + CSS3（Flexbox 布局） |
| 密码加密 | scrypt（通过 werkzeug.security） |
| CSRF 实现 | 基于 secrets 模块的同步令牌模式 |
| 运行地址 | http://0.0.0.0:5000 |
