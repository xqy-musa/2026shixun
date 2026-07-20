# SQL 注入漏洞审计与修复报告

---

<div align="center">
<p><strong>项目名称：</strong>用户信息管理平台</p>
<p><strong>审计日期：</strong>2026 年 7 月 20 日</p>
<p><strong>报告版本：</strong>v2.1 — SQL 注入专项修复</p>
<p><strong>安全等级：</strong>🔴 修复前高危 → 🟢 修复后安全</p>
</div>

---

## 目录

1. [实验概述](#一实验概述)
2. [漏洞总览](#二漏洞总览)
3. [漏洞详细分析](#三漏洞详细分析)
   - [SQL-01 搜索功能 SQL 注入](#sql-01-搜索功能-sql-注入)
   - [SQL-02 注册功能 SQL 注入](#sql-02-注册功能-sql-注入)
   - [SQL-03 错误信息回显泄露](#sql-03-错误信息回显泄露)
   - [SQL-04 数据库密码明文存储](#sql-04-数据库密码明文存储)
4. [修复方案](#四修复方案)
5. [修复后安全验证](#五修复后安全验证)
6. [总结与建议](#六总结与建议)

---

## 一、实验概述

### 1.1 实验背景

本次实验对「用户信息管理平台」项目的 SQL 数据库交互代码进行了全面的安全审计。该项目是一个基于 Python Flask 框架的 Web 应用，提供了用户注册、登录、信息查询等功能，其中注册和搜索功能直接与 SQLite 数据库交互。

### 1.2 审计范围

| 项目 | 内容 |
|------|------|
| 审计对象 | `/opt/Class01/app.py` |
| 审计范围 | 所有与 SQLite 数据库交互的代码路径 |
| 涉及的数据库文件 | `data/users.db` |
| 涉及的数据库表 | `users`（含 id, username, password, email, phone 字段） |
| 审计方法 | 白盒代码审计 + 黑盒注入测试 |

### 1.3 审计工具

- **代码审计**：人工逐行审查
- **注入验证**：Python sqlite3 命令行测试
- **模拟攻击**：构造经典 SQL 注入 payload 验证

---

## 二、漏洞总览

本次审计共发现 **4 项安全漏洞**，按严重程度分级如下：

| 编号 | 漏洞名称 | 严重程度 | 影响范围 | 修复状态 |
|------|----------|----------|----------|:--------:|
| SQL-01 | 搜索功能 SQL 注入 | 🔴 **高危** | 全部用户数据 | ✅ 已修复 |
| SQL-02 | 注册功能 SQL 注入 | 🔴 **高危** | 全部用户数据 | ✅ 已修复 |
| SQL-03 | 错误信息回显泄露 | 🟡 **中危** | 数据库结构信息 | ✅ 已修复 |
| SQL-04 | 数据库密码明文存储 | 🟡 **中危** | 全部用户账号 | ✅ 已修复 |

### 风险量化评分（CVSS 3.1）

| 漏洞编号 | 攻击向量 | 攻击复杂度 | 权限要求 | 影响范围 | 基础得分 |
|----------|----------|------------|----------|----------|:--------:|
| SQL-01 | 网络 | 低 | 无 | 数据机密性/完整性 | **9.8（严重）** |
| SQL-02 | 网络 | 低 | 无 | 数据机密性/完整性 | **9.8（严重）** |
| SQL-03 | 网络 | 低 | 无 | 数据机密性 | **5.3（中危）** |
| SQL-04 | 本地/网络 | 低 | 通过注入获取 | 数据机密性 | **5.9（中危）** |

---

## 三、漏洞详细分析

---

### SQL-01 搜索功能 SQL 注入

#### 漏洞描述

系统在首页搜索功能中，将用户通过 URL 参数 `keyword` 传入的内容直接使用 `f-string` 拼接到 SQL 查询语句中，未做任何过滤、转义或参数化处理。攻击者可通过构造特殊字符改变 SQL 语句的原始逻辑，实现未授权数据访问。

#### 漏洞位置

- **文件**：`app.py`
- **路由**：`GET /`
- **参数**：`keyword`（URL 查询参数）
- **代码行号**：修复前第 152 行

#### 漏洞代码（修复前）

```python
keyword = request.args.get("keyword", "")
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(sql)
```

#### 漏洞可利用的 Payload

```sql
-- Payload ①：万能查询（绕过搜索限制，获取全部用户）
/?keyword=' OR 1=1 --

-- Payload ②：联合查询（获取任意字段数据）
/?keyword=' UNION SELECT 1,2,3,4 --

-- Payload ③：拖库 — 获取数据库元数据
/?keyword=' UNION SELECT 1,sql,3,4 FROM sqlite_master --

-- Payload ④：拖库 — 获取用户名和密码
/?keyword=' UNION SELECT 1,username,password,phone FROM users --
```

#### 复现步骤（Burp Suite）

```
Step 1: 打开 Burp Suite，配置浏览器代理
Step 2: 访问 http://<target>:5000/ 并登录
Step 3: 在搜索框中输入以下 payload：
        ' OR 1=1 --
Step 4: 观察结果页面显示出全部用户数据
─────────────────────────────────────────
Step 5: 使用 Burp Repeater 发送恶意请求：
        GET /?keyword=' UNION SELECT 1,username,password,phone FROM users --
Step 6: 观察响应中所有用户的密码明文被回显
```

#### 可能造成的危害

| 危害类型 | 说明 |
|----------|------|
| 数据泄露 | 攻击者可获取 users 表中所有记录，包括密码字段 |
| 权限提升 | 通过泄露的账号密码登录系统 |
| 进一步攻击 | 利用 sqlite_master 获取数据库结构，实施更精准的攻击 |

---

### SQL-02 注册功能 SQL 注入

#### 漏洞描述

系统在用户注册功能中，将表单提交的四个字段（用户名、密码、邮箱、手机号）全部通过 `f-string` 拼接插入 SQLite 数据库，攻击者可在任意输入框中注入 SQL 语句。

#### 漏洞位置

- **文件**：`app.py`
- **路由**：`POST /register`
- **参数**：`username`、`password`、`email`、`phone`（POST 表单字段）
- **代码行号**：修复前第 202 行

#### 漏洞代码（修复前）

```python
username = request.form.get("username", "")
password = request.form.get("password", "")
email = request.form.get("email", "")
phone = request.form.get("phone", "")
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
c.execute(sql)
```

#### 漏洞可利用的 Payload

```sql
-- Payload ①：插入多条数据（用户名输入框注入）
用户名: a'), ('b', 'b_pwd', 'b@b.com', '999

-- Payload ②：数据覆写（利用唯一约束冲突搞破坏）
用户名: admin', 'override'), ('evil
密码: x
邮箱: x
手机: x

-- Payload ③：子查询探测
用户名: ' || (SELECT sql FROM sqlite_master LIMIT 1) || '
```

#### 复现步骤（Burp Suite）

```
Step 1: 打开 Burp Suite，开启拦截
Step 2: 访问 http://<target>:5000/register
Step 3: 填写注册表单并提交，Burp 拦截到 POST 请求
Step 4: 将 POST Body 修改为：
        username=a') , ('b','b_pwd','b@b.com','999&password=123&email=x&phone=x
Step 5: 发送请求
Step 6: 数据库中同时插入了两条记录
```

#### 可能造成的危害

| 危害类型 | 说明 |
|----------|------|
| 数据污染 | 攻击者可批量插入恶意数据，污染数据库 |
| 数据篡改 | 可能覆盖已有用户记录 |
| 信息探测 | 通过报错信息推断数据库结构 |

---

### SQL-03 错误信息回显泄露

#### 漏洞描述

注册功能在 SQL 执行出错时，将数据库抛出的异常信息直接展示在页面上，攻击者可通过构造不同的闭合语法，利用报错信息反向推导数据库结构，辅助完成 SQL 注入。

#### 漏洞位置

- **文件**：`app.py`
- **路由**：`POST /register`
- **代码行号**：修复前第 215 行

#### 漏洞代码（修复前）

```python
except Exception as e:
    return render_template("register.html", error=f"注册失败：{e}")
```

#### 漏洞可利用的 Payload

```sql
-- 测试单引号闭合
用户名: test'
-- 页面返回错误：注册失败：near "test''": syntax error

-- 测试双引号闭合
用户名: test"
-- 页面返回不同的错误信息

-- 通过逐步调整，攻击者可确定正确的注入语法
用户名: '); SELECT * FROM users --
-- 页面返回错误信息中泄露了字段信息
```

#### 复现步骤（Burp Suite）

```
Step 1: 访问 http://<target>:5000/register
Step 2: 在用户名输入 test'，其他字段随意
Step 3: 提交后页面显示：
        注册失败：UNIQUE constraint failed: users.username
Step 4: 继续测试，逐步构造出正确的注入语法
```

#### 可能造成的危害

| 危害类型 | 说明 |
|----------|------|
| 信息泄露 | 数据库类型、表结构、字段约束等信息被暴露 |
| 辅助攻击 | 降低 SQL 注入的难度，帮助攻击者快速定位注入点 |

---

### SQL-04 数据库密码明文存储

#### 漏洞描述

初始化数据库时，默认用户的密码以明文形式写入 SQLite 数据库文件。一旦数据库文件被下载或通过 SQL 注入被提取，所有用户的密码直接暴露。

#### 漏洞位置

- **文件**：`app.py`
- **函数**：`init_db()`
- **代码行号**：修复前第 39-41 行

#### 漏洞代码（修复前）

```python
c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('admin', 'admin123', ...)")
c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('alice', 'alice2025', ...)")
```

#### 利用方式

```
Step 1: 利用 SQL-01 或 SQL-02 注入获取数据
Step 2: 查询结果中密码字段为明文 "admin123" / "alice2025"
Step 3: 直接使用获取的密码登录系统
```

#### 可能造成的危害

| 危害类型 | 说明 |
|----------|------|
| 账号失窃 | 密码明文存储，泄露即失窃 |
| 横向渗透 | 用户常复用密码，可能危及其他系统 |
| 合规风险 | 违反等保 2.0 / GDPR 等法规的数据加密要求 |

---

## 四、修复方案

### 4.1 修复策略总览

本次修复遵循 **「最小改动、全面覆盖、纵深防御」** 原则：

| 漏洞编号 | 修复策略 | 具体措施 |
|----------|----------|----------|
| SQL-01 | 参数化查询 | 将 f-string 拼接改为 `?` 占位符传参 |
| SQL-02 | 参数化查询 + 密码哈希 | 将 f-string 拼接改为 `?` 占位符传参，密码哈希后存储 |
| SQL-03 | 错误信息抽象 | 异常信息仅记录到日志，页面显示通用错误提示 |
| SQL-04 | 密码哈希存储 | 使用 `generate_password_hash()` 加密后再写入数据库 |

### 4.2 各漏洞详细修复

#### SQL-01 修复：搜索功能

**修复原理**：使用参数化查询（Parameterized Query），将 SQL 语句与数据分离。用户输入的值通过 `?` 占位符传递，数据库引擎自动对其进行转义处理，确保输入不会被解释为 SQL 代码。

```python
# 【修复前】存在 SQL 注入
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%'"

# 【修复后】使用参数化查询，安全可靠
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
like_pattern = f"%{keyword}%"
c.execute(sql, (like_pattern, like_pattern))
```

#### SQL-02 修复：注册功能

**修复原理**：同样使用参数化查询防止注入，同时增加密码哈希存储和基础输入校验。

```python
# 【修复前】存在 SQL 注入 + 密码明文
sql = f"INSERT INTO users (...) VALUES ('{username}', '{password}', ...)"

# 【修复后】参数化查询 + 密码哈希 + 输入校验
if not username or not password:
    return render_template("register.html", error="用户名和密码不能为空")

sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
hashed_pwd = generate_password_hash(password)
c.execute(sql, (username, hashed_pwd, email, phone))
```

#### SQL-03 修复：错误信息隐藏

**修复原理**：将数据库异常的详细错误信息记录到服务器日志（仅供管理员调试），前端页面仅显示通用的错误提示，防止攻击者通过报错信息探测数据库结构。

```python
# 【修复前】详细错误暴露给用户
return render_template("register.html", error=f"注册失败：{e}")

# 【修复后】错误写入服务器日志，用户看到通用提示
except sqlite3.IntegrityError:
    return render_template("register.html", error="该用户名已被注册")
except Exception as e:
    print(f"[SQL] 插入出错: {e}")  # 仅记录到控制台
    return render_template("register.html", error="注册失败，请稍后重试")
```

#### SQL-04 修复：密码哈希存储

**修复原理**：使用 `werkzeug.security` 模块的 `generate_password_hash()` 函数对密码进行哈希加密后再写入数据库。该函数使用 **scrypt** 算法（迭代 32768 轮、8 并行、1 线程），是不可逆的加密哈希，即使数据库泄露也无法还原出原始密码。

```python
# 【修复前】密码明文存储
c.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")

# 【修复后】密码哈希存储
from werkzeug.security import generate_password_hash
hashed_pwd = generate_password_hash("admin123")
c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", hashed_pwd))
```

### 4.3 修复前后代码对比

| 对比项 | 修复前 | 修复后 |
|--------|--------|--------|
| SQL 查询方式 | `f"SELECT ... WHERE field='{input}'"` | `"SELECT ... WHERE field=?"` + 参数传入 |
| SQL 插入方式 | `f"INSERT INTO ... VALUES ('{input}')"` | `"INSERT INTO ... VALUES (?)"` + 参数传入 |
| 密码存储 | 明文 `"admin123"` | scrypt 哈希 `"scrypt:32768:8:1$..."` |
| 错误信息 | `f"注册失败：{e}"`（含数据库详情） | `"该用户名已被注册"`（通用提示） |
| 输入校验 | 无任何校验 | 非空校验 |

---

## 五、修复后安全验证

### 5.1 验证环境

| 项目 | 内容 |
|------|------|
| 操作系统 | Kali Linux |
| Python 版本 | 3.11 |
| 数据库 | SQLite 3 |
| 测试方法 | 自动化脚本验证 |

### 5.2 验证结果

#### 验证一：搜索功能注入防护 ✅ 通过

```python
# 测试 payload：' OR 1=1 --
keyword = "' OR 1=1 --"
sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
c.execute(sql, ('%' + keyword + '%', '%' + keyword + '%'))
rows = c.fetchall()

# 结果：返回 0 条记录
# 说明：' OR 1=1 -- 被当作普通字符串处理，未执行注入
```

#### 验证二：注册功能注入防护 ✅ 通过

```python
# 测试 payload：用户名 = admin2', 'hacked'); --
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(sql, (username, hashed_pwd, email, phone))

# 结果：用户名被完整插入为 "admin2', 'hacked'); --"
# 说明：恶意字符被当作普通文本处理，未影响 SQL 逻辑
```

#### 验证三：密码哈希存储 ✅ 通过

```python
# 检查数据库中密码字段
cursor = conn.execute("SELECT password FROM users WHERE username='admin'")
password = cursor.fetchone()[0]

# 结果：password = "scrypt:32768:8:1$ScEPlOhFgvPN5GqT$..."
# 验证：以 scrypt 开头，非明文，不可逆向还原
```

#### 验证四：错误信息隐藏 ✅ 通过

| 测试场景 | 页面显示 | 是否泄露敏感信息 |
|----------|----------|:----------------:|
| 用户名重复 | "该用户名已被注册" | ❌ 未泄露 |
| 空用户名 | "用户名和密码不能为空" | ❌ 未泄露 |
| 恶意 SQL 语法 | "注册失败，请稍后重试" | ❌ 未泄露 |

### 5.3 Burp Suite 验证步骤

```
────────────────────────────────────────────────────────────
场景：验证搜索功能 SQL 注入已修复
────────────────────────────────────────────────────────────

1. 启动 Burp Suite，配置浏览器代理
2. 访问 http://<target>:5000/ 并登录（admin/admin123）
3. 在搜索框中输入：' OR 1=1 --
4. 观察结果 → 页面显示"无搜索结果"
   ✅ 注入未生效，参数化查询正常工作

────────────────────────────────────────────────────────────
场景：验证注册功能 SQL 注入已修复
────────────────────────────────────────────────────────────

1. 访问 http://<target>:5000/register
2. 使用 Burp 拦截 POST 请求
3. 修改 POST Body：
   username=test' UNION SELECT * FROM users --&password=123&email=x&phone=x
4. 发送请求 → 注册成功，用户名为完整字符串
5. 使用该用户名登录 → 登录成功
   ✅ 注入字符未被解析为 SQL 代码，仅作为普通文本存储
```

### 5.4 修复前后对比矩阵

| 测试项 | 修复前 | 修复后 |
|--------|:------:|:------:|
| `' OR 1=1 --` 搜索 | 🔴 返回全部用户 | 🟢 返回 0 条 |
| `' UNION SELECT 1,2,3,4 --` 搜索 | 🔴 联合查询成功 | 🟢 返回 0 条 |
| 注册注入多条数据 | 🔴 成功插入 | 🟢 作为普通文本插入 |
| 报错页面泄露 SQL 详情 | 🔴 泄露 | 🟢 通用提示 |
| 数据库密码可读 | 🔴 明文 | 🟢 scrypt 哈希 |

---

## 六、总结与建议

### 6.1 修复成果

本次 SQL 注入专项审计共发现 **4 项漏洞**（高危 2 项、中危 2 项），已全部完成修复。经过自动化测试和手动验证，所有注入攻击均被有效拦截，系统目前处于安全状态。

### 6.2 根本原因分析

本次漏洞的根本原因可以归结为以下三点：

| 根源 | 说明 | 涉及漏洞 |
|------|------|----------|
| **SQL 语句与数据未分离** | 使用 f-string 直接将用户输入嵌入 SQL 语句 | SQL-01, SQL-02 |
| **过度信息暴露** | 将系统内部错误信息直接呈现给用户 | SQL-03 |
| **敏感数据未加密** | 密码等敏感信息以可逆形式存储 | SQL-04 |

### 6.3 安全编码建议

为防止类似问题再次发生，建议在后续开发中遵循以下原则：

1. **始终坚持使用参数化查询**
   - 所有 SQL 操作必须使用 `?` 占位符传参
   - 禁止使用任何形式的字符串拼接构造 SQL
   - 这条规则没有例外

2. **错误信息分级展示**
   - 开发环境：可显示详细错误信息
   - 生产环境：仅显示通用错误提示，详细错误写入日志

3. **敏感数据加密存储**
   - 密码必须使用 bcrypt / scrypt / argon2 等专用哈希算法
   - 邮箱、手机号等个人隐私数据应加密或脱敏存储

4. **纵深防御**
   - 输入校验（前端 + 后端双重验证）
   - 最小权限原则（数据库账户只授予必需权限）
   - 定期安全审计（代码审查 + 渗透测试）

### 6.4 建议后续修复项

| 优先级 | 建议项 | 说明 |
|--------|--------|------|
| 🔴 高 | 添加密码复杂度校验 | 注册时要求密码长度 ≥ 8 位，包含字母和数字 |
| 🟡 中 | 登录失败次数限制 | 防止暴力破解，连续失败 5 次后锁定 15 分钟 |
| 🟡 中 | HTTPS 传输加密 | 防止中间人攻击窃取会话和密码 |
| 🟢 低 | 会话超时自动登出 | 增加前端心跳检测，用户无操作 30 分钟后自动退出 |

---

<div align="center">
<p><strong>报告结束</strong></p>
<p>— 本报告由安全审计工具自动生成，所有漏洞均经过人工验证确认 —</p>
</div>
