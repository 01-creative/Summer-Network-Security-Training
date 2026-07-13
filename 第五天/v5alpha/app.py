import os
import re
import sys
import time
# imghdr was removed in Python 3.13. The try/except handles both
# the standard library version (< 3.13) and the 'standard-imghdr'
# backport for 3.13+. If neither is available, a magic-byte fallback
# is used in validate_image_content().
try:
    import imghdr
except ImportError:
    imghdr = None
import sqlite3
import secrets
import logging
from uuid import uuid4
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

app = Flask(__name__)
if os.environ.get("BEHIND_PROXY", "0") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ============================================================
# 基础配置
# ============================================================
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
PORT = int(os.environ.get("FLASK_PORT", "5000"))
SESSION_SECURE = os.environ.get("FLASK_SESSION_SECURE", "1") == "1"

# ============================================================
# 数据库路径
# ============================================================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DB_DIR, "users.db")

# UID 分配常量
UID_SYSTEM_RESERVED = 10000       # 0-10000 系统保留
UID_HARD_LIMIT = 1000000          # 硬上限
UID_RANGE_SIZE = 1000             # 每次分配的区间大小


# ============================================================
# 数据库初始化
# ============================================================
def get_db():
    """获取数据库连接，启用 row_factory 以便字典式访问"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """初始化数据库：创建目录、检查架构迁移、建表、插入默认用户"""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = get_db()
    try:
        # 检查是否需要迁移旧架构（无 uid 列则重建）
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        )
        if cursor.fetchone():
            cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
            if "uid" not in cols:
                logger.info("检测到旧版数据库架构（缺少 uid 列），正在迁移...")
                conn.execute("DROP TABLE users")
                logger.info("旧表已删除，将按新架构重建")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                uid INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                role TEXT DEFAULT 'user',
                balance INTEGER DEFAULT 0,
                first_login INTEGER DEFAULT 0,
                session_version INTEGER DEFAULT 1
            )
        """)

        # 插入默认用户（系统保留 UID: admin=1, alice=2, first_login=1）
        # 初始密码必须通过环境变量注入，严禁在源码中硬编码
        admin_pwd = os.environ.get("INIT_PWD_ADMIN", "")
        alice_pwd = os.environ.get("INIT_PWD_ALICE", "")
        if not admin_pwd:
            print("[致命错误] 必须设置环境变量 INIT_PWD_ADMIN 以指定 admin 初始密码")
            sys.exit(1)
        if not alice_pwd:
            print("[致命错误] 必须设置环境变量 INIT_PWD_ALICE 以指定 alice 初始密码")
            sys.exit(1)

        conn.execute(
            "INSERT OR IGNORE INTO users (uid, username, password, email, phone, role, balance, first_login, session_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "admin", generate_password_hash(admin_pwd),
             "admin@example.com", "13800138000", "admin", 99999, 1, 1)
        )
        conn.execute(
            "INSERT OR IGNORE INTO users (uid, username, password, email, phone, role, balance, first_login, session_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (2, "alice", generate_password_hash(alice_pwd),
             "alice@example.com", "13900139001", "user", 100, 1, 1)
        )

        conn.commit()
        logger.info("数据库初始化完成")
    finally:
        conn.close()


# ============================================================
# UID 分配
# ============================================================

def allocate_uid():
    """
    从当前未满区间中随机分配一个空闲 UID。
    区间大小为 UID_RANGE_SIZE，从 UID_SYSTEM_RESERVED+1 开始逐区间查找。
    返回 None 表示已达硬上限，无法分配。
    """
    conn = get_db()
    try:
        range_start = UID_SYSTEM_RESERVED + 1  # 10001

        while range_start < UID_HARD_LIMIT:
            range_end = range_start + UID_RANGE_SIZE - 1
            if range_end >= UID_HARD_LIMIT:
                range_end = UID_HARD_LIMIT - 1

            # 查询当前区间内已被占用的 UID
            used = set(
                row[0] for row in conn.execute(
                    "SELECT uid FROM users WHERE uid >= ? AND uid <= ?",
                    (range_start, range_end)
                ).fetchall()
            )

            # 计算空闲 UID 列表
            free = [u for u in range(range_start, range_end + 1) if u not in used]
            if free:
                return secrets.choice(free)

            range_start += UID_RANGE_SIZE

        return None  # 所有区间已满
    finally:
        conn.close()


# ============================================================
# 数据库辅助函数
# ============================================================

def db_get_user_by_username(username):
    """通过用户名获取完整用户信息（含密码哈希），不存在返回 None"""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def db_get_user_full(uid):
    """通过 UID 获取完整用户信息（含密码哈希），不存在返回 None"""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE uid = ?",
            (uid,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def db_get_user_safe(uid):
    """通过 UID 获取用户安全信息（排除密码），不存在返回 None"""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT uid, username, email, phone, role, balance, first_login, session_version "
            "FROM users WHERE uid = ?",
            (uid,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def db_insert_user(uid, username, password_hash, email, phone):
    """插入新用户，返回 (success, error_message)"""
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (uid, username, password, email, phone) VALUES (?, ?, ?, ?, ?)",
            (uid, username, password_hash, email, phone)
        )
        conn.commit()
        return True, ""
    except sqlite3.IntegrityError:
        return False, "用户名已存在"
    except Exception as e:
        logger.error(f"插入用户失败: {e}")
        return False, "注册失败，请稍后再试"
    finally:
        conn.close()


def db_update_user_password(uid, new_password_hash):
    """更新用户密码，同时递增 session_version 并取消首次登录标记"""
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET password = ?, first_login = 0, session_version = session_version + 1 "
            "WHERE uid = ?",
            (new_password_hash, uid)
        )
        conn.commit()
    finally:
        conn.close()


def db_update_user_info(uid, email, phone, new_username=None):
    """
    更新用户信息（邮箱、手机号，可选修改用户名）。
    返回 (success, error_message)
    """
    conn = get_db()
    try:
        if new_username:
            conn.execute(
                "UPDATE users SET email = ?, phone = ?, username = ? WHERE uid = ?",
                (email, phone, new_username, uid)
            )
        else:
            conn.execute(
                "UPDATE users SET email = ?, phone = ? WHERE uid = ?",
                (email, phone, uid)
            )
        conn.commit()
        return True, ""
    except sqlite3.IntegrityError:
        return False, "用户名已存在"
    except Exception as e:
        logger.error(f"更新用户信息失败: {e}")
        return False, "更新失败，请稍后再试"
    finally:
        conn.close()


def db_get_session_version(uid):
    """获取用户当前 session_version"""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT session_version FROM users WHERE uid = ?",
            (uid,)
        ).fetchone()
        return row["session_version"] if row else 0
    finally:
        conn.close()


def db_update_balance(uid, amount):
    """使用参数化 SQL 更新用户余额（`balance = balance + ?`）。返回 True 表示成功。"""
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET balance = balance + ? WHERE uid = ?",
            (amount, uid)
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"更新余额失败 (uid={uid}): {e}")
        return False
    finally:
        conn.close()


def db_search_users(keyword):
    """根据 username 和 email 进行模糊搜索，使用参数化查询"""
    conn = get_db()
    try:
        # 过滤 LIKE 通配符，防止批量导出或逐字符枚举
        safe_keyword = keyword.replace("%", "").replace("_", "")
        if len(safe_keyword) < 1:
            return []
        pattern = f"%{safe_keyword}%"
        rows = conn.execute(
            "SELECT uid, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
            (pattern, pattern)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


# ============================================================
# 黑盒修复1：Debug 模式安全加固
# ============================================================
if DEBUG:
    print("""
╔══════════════════════════════════════════════════════════╗
║  ⚠️  警告: Flask 正在以 DEBUG 模式运行!                   ║
║  Debug 模式会暴露 Werkzeug 交互式调试控制台，              ║
║  可能导致远程代码执行 (RCE)。                              ║
║  此模式仅允许在本地开发环境使用，禁止对外暴露。            ║
║  确认这是开发环境吗？(y/n)                                ║
╚══════════════════════════════════════════════════════════╝
    """)
    if not sys.stdin.isatty() or os.path.exists("/.dockerenv"):
        print("[致命错误] 非交互式环境或Docker环境下不允许 DEBUG 模式启动，请设置 FLASK_DEBUG=0")
        sys.exit(1)
    answer = input("> ").strip().lower()
    if answer != "y":
        print("[已取消] 启动已中止")
        sys.exit(1)
    if HOST != "127.0.0.1" and HOST != "localhost":
        print(f"[安全] DEBUG 模式下 HOST 从 {HOST} 强制改为 127.0.0.1")
        HOST = "127.0.0.1"

# ============================================================
# Secret Key — 环境变量优先，加强校验
# ============================================================
_raw_key = os.environ.get("FLASK_SECRET_KEY", "")
if _raw_key:
    if len(_raw_key) < 32:
        print(f"[致命错误] FLASK_SECRET_KEY 长度仅 {len(_raw_key)} 字符，必须 ≥ 32 字符")
        print("[致命错误] 弱密钥可被暴力猜测导致 Session 伪造攻击，拒绝启动")
        sys.exit(1)
    app.secret_key = _raw_key
else:
    app.secret_key = os.urandom(32).hex()
    print("[信息] 未设置 FLASK_SECRET_KEY，已使用随机密钥（重启后所有 session 将失效）")

# ============================================================
# Session Cookie 安全属性
# ============================================================
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=SESSION_SECURE,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_NAME="session",
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)

# ============================================================
# 自动创建上传目录
# ============================================================
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 允许的图片扩展名白名单
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}
# 允许的 MIME 类型白名单
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}


def allowed_file(filename):
    """检查文件扩展名是否在白名单内"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_image_content(content):
    """
    验证文件内容是否为合法图片（基于魔术字节，支持 imghdr 和降级方案）。
    在写入磁盘之前调用，消除 TOCTOU 风险。
    返回 image_type（如 'jpeg', 'png', 'gif', 'webp'）或 None。
    """
    if imghdr is not None:
        # imghdr.what(None, h=...) 支持内存字节判断
        img_type = imghdr.what(None, h=content)
        if img_type and img_type in ALLOWED_EXTENSIONS:
            return img_type
        return None

    # ---- imghdr 不可用时的魔数降级检测 ----
    if not isinstance(content, bytes):
        return None
    # JPEG: \xFF\xD8\xFF
    if content[:3] == b'\xff\xd8\xff':
        return 'jpeg'
    # PNG
    if content[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    # GIF87a / GIF89a
    if content[:6] in (b'GIF87a', b'GIF89a'):
        return 'gif'
    # WebP: RIFF + size + WEBP
    if len(content) >= 12 and content[:4] == b'RIFF' and content[8:12] == b'WEBP':
        return 'webp'
    return None


# 上传文件大小上限（同时受 Flask MAX_CONTENT_LENGTH 保护）
UPLOAD_MAX_SIZE = 16 * 1024 * 1024

# ============================================================
# 移除 Server 响应头
# ============================================================
@app.after_request
def remove_server_header(response):
    try:
        del response.headers["Server"]
    except (KeyError, TypeError):
        pass
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    if SESSION_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ============================================================
# 413 请求实体过大处理
# ============================================================
@app.errorhandler(413)
def request_entity_too_large(error):
    """当上传超过 MAX_CONTENT_LENGTH 时返回友好提示"""
    uid = session.get("uid")
    if uid:
        return render_template("upload.html",
            error="文件大小超过限制（最大 16MB），请压缩后重新上传"), 413
    return render_template("login.html", error="请求内容过大"), 413


# ============================================================
# 登录频率限制（双窗口 + 用户名维度）
# ============================================================
LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 5
SHORT_THRESHOLD = 3
SHORT_WINDOW_SEC = 60
SHORT_LOCK_SEC = 60

PER_USERNAME_LIMIT = 10
PER_USERNAME_LOCKOUT_MIN = 15

# 时序侧信道 — 假哈希
DUMMY_HASH = generate_password_hash("__dummy_constant_string_for_timing__")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ======================== 辅助函数 ========================

def get_safe_user(uid):
    """返回用户安全信息（排除密码）"""
    return db_get_user_safe(uid)


def get_greeting():
    """根据系统时间返回问候语"""
    hour = datetime.now().hour
    if hour < 6:
        return "夜深了，注意休息"
    elif hour < 9:
        return "早上好"
    elif hour < 12:
        return "上午好"
    elif hour < 14:
        return "中午好"
    elif hour < 18:
        return "下午好"
    elif hour < 22:
        return "晚上好"
    else:
        return "夜深了，注意休息"


def generate_csrf_token():
    """生成 CSRF Token"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf():
    """校验 POST 请求中的 CSRF Token，捕获畸形数据防止 500"""
    if request.method != "POST":
        return True
    try:
        token = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not token or not secrets.compare_digest(token, expected):
            logger.warning(f"CSRF 校验失败，IP: {request.remote_addr}")
            return False
        return True
    except RequestEntityTooLarge:
        # 请求体超过 MAX_CONTENT_LENGTH 时重新抛出，触发 413 错误处理器
        raise
    except Exception:
        logger.warning(f"CSRF 请求解析异常（畸形表单数据），IP: {request.remote_addr}")
        return False


def _make_rate_key(ip, username=None):
    """生成限流用的复合键"""
    if username:
        return f"user:{username}:ip:{ip}"
    return f"ip:{ip}"


def cleanup_login_attempts(now):
    """清理已完全过期的条目"""
    stale_keys = []
    for key, record in LOGIN_ATTEMPTS.items():
        long_expired = (not record.get("locked_until") or now >= record["locked_until"])
        short_expired = (not record.get("short_locked_until") or now >= record["short_locked_until"])
        recent = record.get("recent_failures", [])
        recent_active = [t for t in recent if (now - t).total_seconds() <= SHORT_WINDOW_SEC]
        no_recent = len(recent_active) == 0
        no_count = record.get("count", 0) == 0
        if long_expired and short_expired and no_recent and no_count:
            stale_keys.append(key)
    for key in stale_keys:
        LOGIN_ATTEMPTS.pop(key, None)
    if len(LOGIN_ATTEMPTS) > 10000:
        logger.warning("LOGIN_ATTEMPTS 超过 10000 条，触发强制清理")
        keys = list(LOGIN_ATTEMPTS.keys())
        for key in keys[:len(keys) // 2]:
            LOGIN_ATTEMPTS.pop(key, None)


def check_rate_limit(key, max_attempts, lock_minutes, short_thresh, short_sec, lock_sec):
    """通用限流检查，返回 (allowed, remaining_seconds)"""
    now = datetime.now()
    cleanup_login_attempts(now)

    record = LOGIN_ATTEMPTS.get(key)
    if not record:
        return True, 0

    if record.get("locked_until") and now < record["locked_until"]:
        remaining = int((record["locked_until"] - now).total_seconds())
        return False, remaining

    if record.get("short_locked_until") and now < record["short_locked_until"]:
        remaining = int((record["short_locked_until"] - now).total_seconds())
        return False, remaining

    if record.get("locked_until") and now >= record["locked_until"]:
        record["locked_until"] = None
        record["count"] = 0
    if record.get("short_locked_until") and now >= record["short_locked_until"]:
        record["short_locked_until"] = None
        record["recent_failures"] = []

    LOGIN_ATTEMPTS[key] = record
    return True, 0


def record_rate_failure(key, max_attempts, lock_minutes, short_thresh, short_sec, lock_sec):
    """通用失败记录"""
    now = datetime.now()
    record = LOGIN_ATTEMPTS.get(key, {
        "count": 0, "locked_until": None,
        "recent_failures": [], "short_locked_until": None,
    })
    record["count"] = record.get("count", 0) + 1
    if record["count"] >= max_attempts:
        record["locked_until"] = now + timedelta(minutes=lock_minutes)
        logger.warning(f"[限流锁定] {key} 累计失败{record['count']}次，锁定{lock_minutes}分钟")

    recent = record.get("recent_failures", [])
    recent.append(now)
    recent = [t for t in recent if (now - t).total_seconds() <= short_sec]
    record["recent_failures"] = recent
    if len(recent) >= short_thresh:
        record["short_locked_until"] = now + timedelta(seconds=lock_sec)
        logger.warning(f"[限流短锁] {key} {short_sec}秒内失败{len(recent)}次")

    LOGIN_ATTEMPTS[key] = record


def reset_rate_limit(key):
    """清除指定键的限流记录"""
    LOGIN_ATTEMPTS.pop(key, None)


def validate_password_strength(password):
    """验证密码强度"""
    if len(password) < 8:
        return False, "密码长度不能少于 8 位"
    if not any(c.isupper() for c in password):
        return False, "密码必须包含至少一个大写字母"
    if not any(c.islower() for c in password):
        return False, "密码必须包含至少一个小写字母"
    if not any(c.isdigit() for c in password):
        return False, "密码必须包含至少一个数字"
    if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?`~" for c in password):
        return False, "密码必须包含至少一个特殊字符"
    return True, ""


def sanitize_input(value, field_name):
    """输入防 XSS 校验，使用白名单而非黑名单"""
    if not value:
        return True, ""
    if re.search(r'<[^>]*>', value):
        return False, f"{field_name} 不允许包含 HTML 标签"
    if field_name == "邮箱":
        if not re.match(r'^[a-zA-Z0-9@._+\-]+$', value):
            return False, f"{field_name} 包含不允许的字符"
    if field_name == "手机":
        if not re.match(r'^\+?\d[\d\-]*$', value):
            return False, f"{field_name} 包含不允许的字符"
    return True, ""


# ======================== 模板上下文注入 ========================

@app.context_processor
def inject_template_vars():
    """向模板注入全局变量，通过 uid 查找当前用户名"""
    uid = session.get("uid")
    current_username = None
    if uid:
        user = db_get_user_safe(uid)
        if user:
            current_username = user["username"]
    return {
        "csrf_token": session.get("csrf_token", ""),
        "current_username": current_username,
    }


# ======================== 全局钩子 ========================

@app.before_request
def enforce_password_change():
    """强制首次登录改密不可绕过（仅系统默认用户触发）"""
    uid = session.get("uid")
    if uid:
        user = db_get_user_safe(uid)
        if user and user.get("first_login"):
            if request.endpoint not in ("change_password", "logout", "static"):
                return redirect(url_for("change_password"))


@app.before_request
def enforce_session_version():
    """改密后旧 Session 失效"""
    uid = session.get("uid")
    if uid:
        sess_ver = session.get("session_version", 0)
        user_ver = db_get_session_version(uid)
        if sess_ver != user_ver:
            logger.info(f"用户 uid={uid} session 版本不匹配，强制登出")
            session.clear()
            return redirect(url_for("login"))


# ======================== 路由 ========================

@app.route("/")
def index():
    uid = session.get("uid")
    user = db_get_user_safe(uid) if uid else None
    username = user["username"] if user else None
    greeting = get_greeting()
    return render_template("index.html", username=username, user=user, greeting=greeting)


# ============================================================
# [故意漏洞] 动态页面加载 — 路径穿越 / 文件包含
# 漏洞原理：
#   1. name 参数未做任何路径合法性校验，直接拼接到文件路径
#   2. 未使用 os.path.abspath() 或 os.path.realpath() 限定目录范围
#   3. 未过滤 ../ 等目录穿越序列
#   4. 攻击者可借 /page?name=../app 读取 app.py 源码
#      或 /page?name=../../../etc/passwd 读取系统文件
# ============================================================
@app.route("/page")
def dynamic_page():
    """动态页面加载 — 存在路径穿越漏洞"""
    name = request.args.get("name", "")
    if not name:
        return redirect(url_for("index"))

    # 故意漏洞：直接拼接用户输入，不使用 os.path.abspath 限制目录
    page_path = os.path.join("pages", name)

    page_content = None

    # 尝试直接读取路径（漏洞点：未校验路径合法性）
    try:
        with open(page_path, "r", encoding="utf-8") as f:
            page_content = f.read()
    except (IOError, OSError):
        pass

    # 如果找不到，尝试加 .html 后缀
    if page_content is None:
        try:
            with open(page_path + ".html", "r", encoding="utf-8") as f:
                page_content = f.read()
        except (IOError, OSError):
            pass

    if page_content is None:
        page_content = "<p>页面不存在</p>"

    uid = session.get("uid")
    user = db_get_user_safe(uid) if uid else None
    username = user["username"] if user else None
    greeting = get_greeting()
    return render_template(
        "index.html",
        username=username,
        user=user,
        greeting=greeting,
        page_content=page_content,
        page_name=name,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not validate_csrf():
            return render_template("login.html", error="请求校验失败，请刷新页面后重试")

        username = request.form.get("username", "").strip().replace("\n", " ").replace("\r", " ")
        password = request.form.get("password", "")

        client_ip = request.remote_addr

        # IP + 用户名双重维度限流
        ip_key = _make_rate_key(client_ip)
        user_key = _make_rate_key(client_ip, username)

        ip_allowed, _ = check_rate_limit(ip_key, MAX_ATTEMPTS, LOCKOUT_MINUTES,
                                          SHORT_THRESHOLD, SHORT_WINDOW_SEC, SHORT_LOCK_SEC)
        user_allowed, _ = check_rate_limit(user_key, PER_USERNAME_LIMIT, PER_USERNAME_LOCKOUT_MIN,
                                            SHORT_THRESHOLD, SHORT_WINDOW_SEC, SHORT_LOCK_SEC)

        if not ip_allowed or not user_allowed:
            return render_template("login.html", error="请求过于频繁，请稍后再试")

        # 时序侧信道防御
        user_record = db_get_user_by_username(username)
        if user_record is not None:
            pwd_valid = check_password_hash(user_record["password"], password)
        else:
            check_password_hash(DUMMY_HASH, password)
            pwd_valid = False

        if pwd_valid:
            # Session 绑定 UID
            session["uid"] = user_record["uid"]
            session["session_version"] = user_record["session_version"]
            reset_rate_limit(ip_key)
            reset_rate_limit(user_key)
            logger.info(f"用户 '{username}' (uid={user_record['uid']}) 登录成功")

            if user_record.get("first_login", False):
                session["force_change_password"] = True
                return redirect(url_for("change_password"))

            return redirect(url_for("index"))

        record_rate_failure(ip_key, MAX_ATTEMPTS, LOCKOUT_MINUTES,
                            SHORT_THRESHOLD, SHORT_WINDOW_SEC, SHORT_LOCK_SEC)
        record_rate_failure(user_key, PER_USERNAME_LIMIT, PER_USERNAME_LOCKOUT_MIN,
                            SHORT_THRESHOLD, SHORT_WINDOW_SEC, SHORT_LOCK_SEC)
        logger.warning(f"用户 '{username}' 从 {client_ip} 登录失败")
        return render_template("login.html", error="用户名或密码错误")

    generate_csrf_token()
    return render_template("login.html")


# ============================================================
# 用户注册
# ============================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not validate_csrf():
            return render_template("register.html", error="请求校验失败，请刷新页面后重试")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 长度校验
        if len(username) > 50:
            return render_template("register.html", error="用户名不能超过50个字符")
        if len(password) > 128:
            return render_template("register.html", error="密码不能超过128个字符")
        if len(email) > 255:
            return render_template("register.html", error="邮箱不能超过255个字符")
        if len(phone) > 32:
            return render_template("register.html", error="手机号不能超过32个字符")

        # 用户名不能为空
        if not username:
            return render_template("register.html", error="用户名不能为空")

        # 密码不能为空
        if not password:
            return render_template("register.html", error="密码不能为空")

        # 两次密码一致
        if password != confirm_password:
            return render_template("register.html", error="两次输入的密码不一致")

        # 密码强度
        valid, msg = validate_password_strength(password)
        if not valid:
            return render_template("register.html", error=msg)

        # 邮箱格式
        if email and "@" not in email:
            return render_template("register.html", error="请输入有效的邮箱地址")

        # XSS 输入过滤
        if email:
            ok, err = sanitize_input(email, "邮箱")
            if not ok:
                return render_template("register.html", error=err)
        if phone:
            ok, err = sanitize_input(phone, "手机")
            if not ok:
                return render_template("register.html", error=err)

        # 检查用户名是否已存在
        if db_get_user_by_username(username):
            return render_template("register.html", error="用户名已存在，请选择其他用户名")

        # 分配 UID（注册成功时才分配）
        uid = allocate_uid()
        if uid is None:
            return render_template("register.html", error="注册失败：用户数量已达上限，请联系管理员")

        # 插入数据库
        password_hash = generate_password_hash(password)
        success, db_error = db_insert_user(uid, username, password_hash, email, phone)
        if not success:
            return render_template("register.html", error=db_error)

        logger.info(f"新用户 '{username}' (uid={uid}) 注册成功")
        return redirect(url_for("login", registered="1"))

    generate_csrf_token()
    return render_template("register.html")


# ============================================================
# 用户搜索
# ============================================================
@app.route("/search")
def search():
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))
    user = db_get_user_safe(uid)
    username = user["username"] if user else None
    greeting = get_greeting()

    keyword = request.args.get("keyword", "").strip()
    search_results = []
    search_performed = False

    if keyword:
        search_performed = True
        start_time = time.time()
        search_results = db_search_users(keyword)
        elapsed_ms = int((time.time() - start_time) * 1000)

        safe_log_keyword = keyword.replace("\n", " ").replace("\r", " ")
        logger.info(
            f"[搜索] 方法={request.method} | keyword=\"{safe_log_keyword}\" | "
            f"耗时={elapsed_ms}ms | 结果数={len(search_results)}"
        )

    return render_template(
        "index.html",
        username=username,
        user=user,
        greeting=greeting,
        keyword=keyword,
        search_results=search_results,
        search_performed=search_performed,
    )


# ============================================================
# Logout — POST + CSRF
# ============================================================
@app.route("/logout", methods=["POST"])
def logout():
    if not validate_csrf():
        return redirect(url_for("index"))
    uid = session.get("uid")
    logger.info(f"用户 uid={uid} 已登出")
    session.clear()
    return redirect(url_for("index"))


# ======================== 修改密码 ========================

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))

    user = db_get_user_full(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))
    is_forced = user.get("first_login", False)

    if request.method == "POST":
        if not validate_csrf():
            return render_template("change_password.html",
                error="请求校验失败，请刷新页面后重试", is_forced=is_forced)

        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not is_forced:
            if not check_password_hash(user["password"], old_password):
                return render_template("change_password.html",
                    error="原密码错误", is_forced=False)

        valid, msg = validate_password_strength(new_password)
        if not valid:
            return render_template("change_password.html", error=msg, is_forced=is_forced)

        if new_password != confirm_password:
            return render_template("change_password.html",
                error="两次输入的新密码不一致", is_forced=is_forced)

        db_update_user_password(uid, generate_password_hash(new_password))
        session["session_version"] = db_get_session_version(uid)
        session.pop("force_change_password", None)
        logger.info(f"用户 uid={uid} 修改密码成功 (强制={is_forced})")

        return render_template("change_password.html",
            success="密码修改成功！", is_forced=False, changed=True)

    generate_csrf_token()
    return render_template("change_password.html", is_forced=is_forced)


# ======================== 个人中心 ========================

@app.route("/profile", methods=["GET", "POST"])
def profile():
    uid = session.get("uid")
    if not uid:
        session.clear()
        return redirect(url_for("login"))

    user = db_get_user_safe(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))

    greeting = get_greeting()

    if request.method == "POST":
        if not validate_csrf():
            return render_template("profile.html", user=user, greeting=greeting,
                info_error="请求校验失败，请刷新页面后重试")

        action = request.form.get("action", "")

        if action == "change_password":
            old_password = request.form.get("old_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            user_full = db_get_user_full(uid)
            if not check_password_hash(user_full["password"], old_password):
                return render_template("profile.html", user=user, greeting=greeting,
                    pwd_error="原密码错误")

            valid, msg = validate_password_strength(new_password)
            if not valid:
                return render_template("profile.html", user=user, greeting=greeting,
                    pwd_error=msg)

            if new_password != confirm_password:
                return render_template("profile.html", user=user, greeting=greeting,
                    pwd_error="两次输入的新密码不一致")

            db_update_user_password(uid, generate_password_hash(new_password))
            session["session_version"] = db_get_session_version(uid)
            logger.info(f"用户 uid={uid} 在个人中心修改密码")
            return render_template("profile.html", user=user, greeting=greeting,
                pwd_success="密码修改成功")

        elif action == "update_info":
            new_username = request.form.get("username", "").strip()
            new_email = request.form.get("email", "").strip()
            new_phone = request.form.get("phone", "").strip()

            errors = []

            # 用户名校验
            if not new_username:
                errors.append("用户名不能为空")
            elif len(new_username) > 50:
                errors.append("用户名不能超过50个字符")

            # 邮箱校验
            email_ok, email_err = sanitize_input(new_email, "邮箱")
            if not email_ok:
                errors.append(email_err)
            elif not new_email or "@" not in new_email:
                errors.append("请输入有效的邮箱地址")

            # 手机号校验
            phone_ok, phone_err = sanitize_input(new_phone, "手机")
            if not phone_ok:
                errors.append(phone_err)
            elif not new_phone or len(new_phone) < 11:
                errors.append("请输入有效的手机号码（至少11位）")

            if errors:
                return render_template("profile.html", user=user, greeting=greeting,
                    info_error="；".join(errors))

            # 如果用户名有变更，检查是否重复
            username_to_update = new_username if new_username != user["username"] else None
            success, db_error = db_update_user_info(uid, new_email, new_phone, username_to_update)
            if not success:
                return render_template("profile.html", user=user, greeting=greeting,
                    info_error=db_error)

            logger.info(f"用户 uid={uid} 更新了个人信息")

            # 刷新 user 数据
            user = db_get_user_safe(uid)
            return render_template("profile.html", user=user, greeting=greeting,
                info_success="个人信息更新成功")

    generate_csrf_token()
    return render_template("profile.html", user=user, greeting=greeting)


# ============================================================
# 余额充值
# ============================================================

@app.route("/recharge", methods=["POST"])
def recharge():
    """安全余额充值，仅接受 POST 请求。身份仅从 session['uid'] 获取。"""
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))

    user = db_get_user_safe(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))

    greeting = get_greeting()

    if not validate_csrf():
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="请求校验失败，请刷新页面后重试")

    amount_str = request.form.get("amount", "").strip()

    # 严格校验：必须存在且非空
    if not amount_str:
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="金额不能为空")

    # 严格校验：必须能转为数值
    try:
        amount = float(amount_str)
    except (ValueError, TypeError):
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="金额必须是有效的数字")

    # 严格校验：必须 > 0
    if amount <= 0:
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="充值金额必须大于 0")

    # 严格校验：必须 <= 100000
    if amount > 100000:
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="单次充值金额不能超过 100000")

    # 四舍五入到两位小数，防止浮点数精度问题
    amount = round(amount, 2)

    # 使用参数化 SQL 更新余额
    success = db_update_balance(uid, amount)
    if not success:
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="充值失败，请稍后重试")

    logger.info(f"用户 uid={uid} 充值成功: {amount}")
    return redirect(url_for("profile"))


# ============================================================
# 头像上传
# ============================================================
@app.route("/upload", methods=["GET", "POST"])
def upload_avatar():
    """安全头像上传（仅限登录用户）"""
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))

    user = db_get_user_safe(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        if not validate_csrf():
            return render_template("upload.html", error="请求校验失败，请刷新页面后重试")

        try:
            # 检查是否有文件
            if "avatar" not in request.files:
                return render_template("upload.html", error="请选择要上传的图片文件")

            file = request.files["avatar"]
            if not file.filename:
                return render_template("upload.html", error="请选择要上传的图片文件")

            # 文件扩展名白名单校验
            if not allowed_file(file.filename):
                return render_template("upload.html",
                    error="不支持的文件格式，仅允许上传 jpg、jpeg、png、gif、webp 格式的图片")

            # MIME 类型校验（防御纵深：Content-Type 由客户端控制，不可单独依赖）
            mime_type = file.content_type
            if mime_type not in ALLOWED_MIME_TYPES:
                return render_template("upload.html",
                    error=f"不支持的 MIME 类型 '{mime_type}'，仅允许上传图片文件")

            # 安全化文件名（防路径遍历/截断攻击）
            safe_name = secure_filename(file.filename)
            if not safe_name:
                return render_template("upload.html", error="文件名不合法，请重新命名后上传")

            # 若 secure_filename 将扩展名剥离（例如中文或纯点号文件名），重新附上
            original_ext = file.filename.rsplit(".", 1)[1].lower() if "." in file.filename else ""
            if '.' not in safe_name and original_ext in ALLOWED_EXTENSIONS:
                safe_name = safe_name + '.' + original_ext

            # 读取文件内容到内存（关闭 TOCTOU 窗口 + 显式大小检查）
            file_content = file.read()
            file_length = len(file_content)

            # 显式文件大小检查（防御纵深：MAX_CONTENT_LENGTH 在 chunked 编码下可能旁路）
            if file_length > UPLOAD_MAX_SIZE:
                logger.warning(f"用户 uid={uid} 上传文件过大: {file_length} 字节")
                return render_template("upload.html",
                    error="文件大小超过限制（最大 16MB），请压缩后重新上传")

            # 使用 imghdr / 魔数验证真实图片内容（在写入磁盘之前完成）
            image_type = validate_image_content(file_content)
            if image_type is None:
                return render_template("upload.html",
                    error="文件内容不是有效的图片，请上传真正的图片文件")

            # UUID 前缀防止文件覆盖和枚举
            unique_name = f"{uuid4().hex}_{safe_name}"
            save_path = os.path.join(UPLOAD_FOLDER, unique_name)

            # 写入磁盘（此时内容已通过全部安全检查）
            with open(save_path, 'wb') as f:
                f.write(file_content)

            # 生成访问 URL
            image_url = url_for("static", filename=f"uploads/{unique_name}")
            logger.info(f"用户 uid={uid} 上传头像成功: {unique_name} ({image_type}, {file_length} 字节)")

            return render_template("upload.html", success=True, image_url=image_url,
                username=user["username"])

        except RequestEntityTooLarge:
            raise
        except Exception as e:
            logger.error(f"上传头像异常: {e}")
            return render_template("upload.html", error="上传失败，请稍后重试")

    generate_csrf_token()
    return render_template("upload.html")


# ============================================================
# 应用启动：初始化数据库
# ============================================================
init_db()

if __name__ == "__main__":
    print(f"[启动] Debug={DEBUG}, Host={HOST}, Port={PORT}")
    print(f"[启动] Session Cookie: HttpOnly=True, SameSite=Lax, Secure=False (HTTPS部署时请改为True)")
    app.run(debug=DEBUG, host=HOST, port=PORT)
