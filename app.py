from flask import Flask, render_template, request, redirect, session, abort, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import timedelta
import os
import secrets
import re
import sqlite3
import uuid
import imghdr

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)


# ============================================================
# SQLite 数据库初始化
# ============================================================

def init_db():
    """初始化 SQLite 数据库，密码使用哈希存储。"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)
    # 插入默认用户（密码使用哈希存储）
    admin_pwd = generate_password_hash("admin123")
    alice_pwd = generate_password_hash("alice2025")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("admin", admin_pwd, "admin@example.com", "13800138000", 99999))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("alice", alice_pwd, "alice@example.com", "13900139001", 100))
    conn.commit()
    conn.close()


# 应用启动时初始化数据库
init_db()


# ============================================================
# USERS 字典（原有登录功能备份，保持向后兼容）
# ============================================================

def _build_user_db():
    """构建用户数据库，密码使用 scrypt 算法哈希存储。"""
    raw = {
        "admin": {
            "username": "admin",
            "password": "admin123",
            "role": "admin",
            "email": "admin@example.com",
            "phone": "13800138000",
            "balance": 99999,
        },
        "alice": {
            "username": "alice",
            "password": "alice2025",
            "role": "user",
            "email": "alice@example.com",
            "phone": "13900139001",
            "balance": 100,
        },
    }
    db = {}
    for uid, info in raw.items():
        record = info.copy()
        record["password"] = generate_password_hash(record["password"])
        db[uid] = record
    return db


USERS = _build_user_db()


def sanitize_user_info(user_info):
    """构造可供模板安全使用的用户信息字典（脱敏处理）。"""
    if not user_info:
        return None
    return {
        "username": user_info.get("username", ""),
        "role": user_info.get("role", ""),
        "email": user_info.get("email", ""),
        "phone": user_info["phone"][:3] + "****" + user_info["phone"][-4:],
        "balance": "¥{:,.2f}".format(float(user_info["balance"])),
    }


def sanitize_input(text):
    """过滤用户输入，移除 HTML 标签和危险关键字。"""
    if not text:
        return ""
    text = str(text).strip()
    text = re.sub(r"<[^>]*>", "", text)
    text = re.sub(r"javascript\s*:", "", text, flags=re.IGNORECASE)
    return text


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.before_request
def _csrf_protect():
    if request.method == "POST" and request.endpoint != "static":
        token = request.form.get("csrf_token")
        stored = session.get("csrf_token")
        if not token or not stored or token != stored:
            abort(400, "CSRF token 缺失或无效")


@app.context_processor
def _inject_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return {"csrf_token": session["csrf_token"]}


# ============================================================
# 首页（含搜索功能 — 已修复 SQL 注入）
# ============================================================

@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username and username in USERS:
        user = sanitize_user_info(USERS[username])

    # 搜索功能 — 已改用参数化查询修复 SQL 注入
    keyword = request.args.get("keyword", "")
    search_results = None
    if keyword:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # 【修复】使用参数化查询代替 f-string 拼接
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_pattern = f"%{keyword}%"
        print(f"\n[SQL] 执行查询: {sql} (参数: '%{keyword}%')\n")
        try:
            c.execute(sql, (like_pattern, like_pattern))
            rows = c.fetchall()
            search_results = [dict(row) for row in rows]
        except Exception as e:
            print(f"[SQL] 查询出错: {e}")
            search_results = []
        conn.close()

    return render_template("index.html", user=user, search_results=search_results, keyword=keyword)


# ============================================================
# 登录（已整合 SQLite 数据库，注册用户也可以登录）
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")

        # 优先从 USERS 字典验证（保持与原有功能一致）
        user_record = USERS.get(username)
        if user_record and check_password_hash(user_record["password"], password):
            session.clear()
            session.permanent = True
            session["username"] = username
            session["csrf_token"] = secrets.token_hex(32)
            user = sanitize_user_info(user_record)
            return render_template("index.html", user=user)

        # 如果字典中不存在，尝试从 SQLite 数据库验证（注册用户）
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        db_user = c.fetchone()
        conn.close()

        if db_user and check_password_hash(db_user["password"], password):
            session.clear()
            session.permanent = True
            session["username"] = username
            session["csrf_token"] = secrets.token_hex(32)
            # 为 SQLite 用户构建 USERS 格式的信息
            user_data = {
                "username": db_user["username"],
                "role": "user",
                "email": db_user["email"] or "",
                "phone": db_user["phone"] or "",
                "balance": 0,
            }
            USERS[username] = user_data
            USERS[username]["password"] = db_user["password"]
            user = sanitize_user_info(user_data)
            return render_template("index.html", user=user)

        return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")


# ============================================================
# 注册（已修复 SQL 注入，使用参数化查询）
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 基础校验
        if not username or not password:
            return render_template("register.html", error="用户名和密码不能为空")

        # 【修复】使用参数化查询代替 f-string 拼接
        sql = "INSERT INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)"
        # 【修复】密码使用哈希存储
        hashed_pwd = generate_password_hash(password)
        print(f"\n[SQL] 执行插入: {sql} (参数: '{username}', '[哈希密码]', '{email}', '{phone}', 0)\n")

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        try:
            c.execute(sql, (username, hashed_pwd, email, phone, 0))
            conn.commit()
            conn.close()
            return redirect(url_for("login", registered="success"))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="该用户名已被注册")
        except Exception as e:
            print(f"[SQL] 插入出错: {e}")
            conn.close()
            return render_template("register.html", error="注册失败，请稍后重试")

    return render_template("register.html")


# ============================================================
# 文件上传（已修复安全漏洞）
# ============================================================

# 允许上传的文件类型白名单
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}


def allowed_file(filename):
    """检查文件扩展名是否在白名单内。"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择要上传的文件")

        # 【修复】检查文件扩展名
        if not allowed_file(file.filename):
            return render_template("upload.html", error="仅允许上传 jpg、jpeg、png、gif、webp 格式的图片文件")

        # 【修复】防止路径遍历：仅取原始文件名中的基本名称
        original_name = os.path.basename(file.filename)

        # 【修复】使用 UUID 重命名文件，防止文件名冲突和覆盖
        ext = original_name.rsplit(".", 1)[1].lower() if "." in original_name else ""
        safe_filename = f"{uuid.uuid4().hex}.{ext}"

        # 创建上传目录
        upload_dir = os.path.join(app.root_path, "static", "uploads")
        os.makedirs(upload_dir, exist_ok=True)

        # 保存文件
        filepath = os.path.join(upload_dir, safe_filename)
        file.save(filepath)

        # 【修复】验证文件内容是否为真实图片
        if not imghdr.what(filepath):
            os.remove(filepath)
            return render_template("upload.html", error="上传的文件不是有效的图片格式")

        file_url = url_for("static", filename=f"uploads/{safe_filename}")
        return render_template("upload.html", success=True, file_url=file_url, filename=original_name, safe_filename=safe_filename)

    return render_template("upload.html")


# ============================================================
# 个人中心（水平越权漏洞：URL 参数 user_id 可查看任意用户）
# ============================================================

@app.route("/profile")
@login_required
def profile():
    # 从 URL 参数获取 user_id，不从 session 获取
    user_id = request.args.get("user_id")

    # 查询用户数据（不验证当前登录用户和要查询的 user_id 是否匹配）
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, balance FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()

    if not user_data:
        return render_template("profile.html", error="用户不存在")

    return render_template("profile.html", user=dict(user_data))


# ============================================================
# 充值（垂直越权漏洞：未校验 amount 正负，可篡改任意用户余额）
# ============================================================

@app.route("/recharge", methods=["POST"])
@login_required
def recharge():
    user_id = request.form.get("user_id")
    amount = request.form.get("amount", "0")

    # 不做正负校验，直接修改余额
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if row:
        new_balance = row[0] + float(amount)
        c.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user_id))
        conn.commit()

        # 同步更新 USERS 字典中的余额
        c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username_row = c.fetchone()
        if username_row and username_row[0] in USERS:
            USERS[username_row[0]]["balance"] = new_balance

    conn.close()
    return redirect(url_for("profile", user_id=user_id))


# ============================================================
# 登出
# ============================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
