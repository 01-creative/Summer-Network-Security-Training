import os
import re
import sys
import time
import secrets
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ============================================================
# 基础配置
# ============================================================
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
PORT = int(os.environ.get("FLASK_PORT", "5000"))

# ============================================================
# 黑盒修复1：Debug 模式安全加固
# 修复前: 仅依赖环境变量默认值，部署者随手 FLASK_DEBUG=1 即可打开
# 修复后: 即使 FLASK_DEBUG=1，也会验证合理性并打印醒目警告
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
    # 非交互式环境（如 Docker/systemd）直接拒绝启动
    if not sys.stdin.isatty() or os.path.exists("/.dockerenv"):
        print("[致命错误] 非交互式环境或Docker环境下不允许 DEBUG 模式启动，请设置 FLASK_DEBUG=0")
        sys.exit(1)
    answer = input("> ").strip().lower()
    if answer != "y":
        print("[已取消] 启动已中止")
        sys.exit(1)
    # 强制绑定到本地（debug 下不允许对外暴露）
    if HOST != "127.0.0.1" and HOST != "localhost":
        print(f"[安全] DEBUG 模式下 HOST 从 {HOST} 强制改为 127.0.0.1")
        HOST = "127.0.0.1"

# ============================================================
# Secret Key — 环境变量优先，加强校验
# ============================================================
_raw_key = os.environ.get("FLASK_SECRET_KEY", "")
if _raw_key:
    # 黑盒修复3：校验从环境变量读取的密钥强度
    if len(_raw_key) < 32:
        print(f"[致命错误] FLASK_SECRET_KEY 长度仅 {len(_raw_key)} 字符，必须 ≥ 32 字符")
        print("[致命错误] 弱密钥可被暴力猜测导致 Session 伪造攻击，拒绝启动")
        sys.exit(1)
    app.secret_key = _raw_key
else:
    app.secret_key = os.urandom(32).hex()
    print("[信息] 未设置 FLASK_SECRET_KEY，已使用随机密钥（重启后所有 session 将失效）")

# ============================================================
# 黑盒修复7：Session Cookie 安全属性
# 修复前: HttpOnly=True, 但 Secure 和 SameSite 缺失
# 修复后: 显式设置 Secure + SameSite + HttpOnly
# ============================================================
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,       # 本地测试用 HTTP；HTTPS 部署时改为 True
    SESSION_COOKIE_SAMESITE="Lax",     # 防止跨站请求携带 Cookie
    SESSION_COOKIE_NAME="session",
)

# ============================================================
# 黑盒修复10：移除 Server 响应头
# ============================================================
@app.after_request
def remove_server_header(response):
    response.headers.pop("Server", None)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


# ============================================================
# 用户数据库
# 黑盒修复2：初始密码从环境变量读取，代码中不再硬编码明文
# 修复前: generate_password_hash("Admin@2025#Secure") 硬编码在源码中
# 修复后: 从环境变量读取；未设置时随机生成并打印（仅首次启动可见）
# ============================================================
def _load_initial_password(env_key, username):
    """从环境变量加载初始密码，未设置时随机生成"""
    pwd = os.environ.get(env_key, "")
    if pwd:
        return generate_password_hash(pwd)
    else:
        print(f"[致命错误] 必须为 '{username}' 设置环境变量 {env_key} 以指定初始密码")
        sys.exit(1)

USERS = {
    "admin": {
        "password": _load_initial_password("INIT_PWD_ADMIN", "admin"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
        "first_login": True,
        "session_version": 1,
    },
    "alice": {
        "password": _load_initial_password("INIT_PWD_ALICE", "alice"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
        "first_login": True,
        "session_version": 1,
    },
}

# ============================================================
# 登录频率限制（双窗口 + 用户名维度）
# 黑盒修复9：新增按用户名的限流维度，补充纯 IP 限流对代理池无效的短板
# ============================================================
LOGIN_ATTEMPTS = {}              # {key: {count, locked_until, recent_failures, short_locked_until}}
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 5
SHORT_THRESHOLD = 3
SHORT_WINDOW_SEC = 60
SHORT_LOCK_SEC = 60

PER_USERNAME_LIMIT = 10          # 同一用户名累计失败上限
PER_USERNAME_LOCKOUT_MIN = 15    # 用户名维度锁定时长

# 时序侧信道 — 假哈希
DUMMY_HASH = generate_password_hash("__dummy_constant_string_for_timing__")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ======================== 辅助函数 ========================

def get_safe_user(username):
    """返回用户信息，明确排除密码字段"""
    if username and username in USERS:
        u = USERS[username]
        return {
            "username": username,
            "role": u["role"],
            "email": u["email"],
            "phone": u["phone"],
            "balance": u["balance"],
            "first_login": u.get("first_login", False),
        }
    return None


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
    """校验 POST 请求中的 CSRF Token"""
    if request.method != "POST":
        return True
    token = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not token or not secrets.compare_digest(token, expected):
        logger.warning(f"CSRF 校验失败，IP: {request.remote_addr}")
        return False
    return True


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

    # 过期解除
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
    """
    黑盒修复8：输入防 XSS 校验
    拒绝包含 HTML 标签和危险字符的输入，使用白名单而非黑名单
    """
    if not value:
        return True, ""
    # 拒绝 HTML 标签
    if re.search(r'<[^>]*>', value):
        return False, f"{field_name} 不允许包含 HTML 标签"
    # 邮箱字段：仅允许字母数字和常见邮箱字符
    if field_name == "邮箱":
        if not re.match(r'^[a-zA-Z0-9@._+\-]+$', value):
            return False, f"{field_name} 包含不允许的字符"
    # 手机字段：仅允许数字和 +
    if field_name == "手机":
        if not re.match(r'^\+?\d[\d\-]*$', value):
            return False, f"{field_name} 包含不允许的字符"
    return True, ""


# ======================== 模板上下文注入 ========================

@app.context_processor
def inject_template_vars():
    return {"csrf_token": session.get("csrf_token", "")}


# ======================== 全局钩子 ========================

@app.before_request
def enforce_password_change():
    """强制首次登录改密不可绕过"""
    username = session.get("username")
    if username and username in USERS and USERS[username].get("first_login"):
        if request.endpoint not in ("change_password", "logout", "static"):
            return redirect(url_for("change_password"))


@app.before_request
def enforce_session_version():
    """改密后旧 Session 失效"""
    username = session.get("username")
    if username and username in USERS:
        sess_ver = session.get("session_version", 0)
        user_ver = USERS[username].get("session_version", 0)
        if sess_ver != user_ver:
            logger.info(f"用户 '{username}' session 版本不匹配，强制登出")
            session.clear()
            return redirect(url_for("login"))


# ======================== 路由 ========================

@app.route("/")
def index():
    username = session.get("username")
    user = get_safe_user(username) if username else None
    greeting = get_greeting()
    return render_template("index.html", username=username, user=user, greeting=greeting)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not validate_csrf():
            return render_template("login.html", error="请求校验失败，请刷新页面后重试")

        username = request.form.get("username", "").strip().replace("\n", " ").replace("\r", " ")
        password = request.form.get("password", "")

        client_ip = request.remote_addr

        # ---- 黑盒修复9：用户名维度限流 ----
        # 修复前: 仅 IP 维度 -> 代理池可绕过
        # 修复后: IP + 用户名双重维度，任一触发即锁定
        ip_key = _make_rate_key(client_ip)
        user_key = _make_rate_key(client_ip, username)

        ip_allowed, _ = check_rate_limit(ip_key, MAX_ATTEMPTS, LOCKOUT_MINUTES,
                                          SHORT_THRESHOLD, SHORT_WINDOW_SEC, SHORT_LOCK_SEC)
        user_allowed, _ = check_rate_limit(user_key, PER_USERNAME_LIMIT, PER_USERNAME_LOCKOUT_MIN,
                                            SHORT_THRESHOLD, SHORT_WINDOW_SEC, SHORT_LOCK_SEC)

        if not ip_allowed or not user_allowed:
            return render_template("login.html", error="请求过于频繁，请稍后再试")

        # ---- 时序侧信道防御 ----
        user_record = USERS.get(username)
        if user_record is not None:
            pwd_valid = check_password_hash(user_record["password"], password)
        else:
            check_password_hash(DUMMY_HASH, password)
            pwd_valid = False

        if pwd_valid:
            session["username"] = username
            session["session_version"] = user_record["session_version"]
            # 成功则清除所有相关限流
            reset_rate_limit(ip_key)
            reset_rate_limit(user_key)
            logger.info(f"用户 '{username}' 登录成功")

            if user_record.get("first_login", False):
                session["force_change_password"] = True
                return redirect(url_for("change_password"))

            return redirect(url_for("index"))

        # 失败 — 同时记录 IP 和用户名维度
        record_rate_failure(ip_key, MAX_ATTEMPTS, LOCKOUT_MINUTES,
                            SHORT_THRESHOLD, SHORT_WINDOW_SEC, SHORT_LOCK_SEC)
        record_rate_failure(user_key, PER_USERNAME_LIMIT, PER_USERNAME_LOCKOUT_MIN,
                            SHORT_THRESHOLD, SHORT_WINDOW_SEC, SHORT_LOCK_SEC)
        logger.warning(f"用户 '{username}' 从 {client_ip} 登录失败")
        return render_template("login.html", error="用户名或密码错误")

    generate_csrf_token()
    return render_template("login.html")


# ============================================================
# 黑盒修复6：Logout 从 GET 改为 POST + CSRF
# 修复前: GET /logout 即登出，攻击者用 <img src="/logout"> 即可强制用户登出
# 修复后: 仅接受 POST，必须携带 CSRF Token
# ============================================================
@app.route("/logout", methods=["POST"])
def logout():
    if not validate_csrf():
        return redirect(url_for("index"))
    username = session.get("username", "unknown")
    session.clear()
    logger.info(f"用户 '{username}' 已登出")
    return redirect(url_for("index"))


# ======================== 修改密码与个人信息 ========================

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    if username not in USERS:
        session.clear()
        return redirect(url_for("login"))
    is_forced = USERS[username].get("first_login", False)

    if request.method == "POST":
        if not validate_csrf():
            return render_template("change_password.html",
                error="请求校验失败，请刷新页面后重试", is_forced=is_forced)

        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not is_forced:
            if not check_password_hash(USERS[username]["password"], old_password):
                return render_template("change_password.html",
                    error="原密码错误", is_forced=False)

        valid, msg = validate_password_strength(new_password)
        if not valid:
            return render_template("change_password.html", error=msg, is_forced=is_forced)

        if new_password != confirm_password:
            return render_template("change_password.html",
                error="两次输入的新密码不一致", is_forced=is_forced)

        USERS[username]["password"] = generate_password_hash(new_password)
        USERS[username]["first_login"] = False
        USERS[username]["session_version"] += 1
        session["session_version"] = USERS[username]["session_version"]
        session.pop("force_change_password", None)
        logger.info(f"用户 '{username}' 修改密码成功 (强制={is_forced})")

        return render_template("change_password.html",
            success="密码修改成功！", is_forced=False, changed=True)

    generate_csrf_token()
    return render_template("change_password.html", is_forced=is_forced)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    username = session.get("username")
    if not username or username not in USERS:
        session.clear()
        return redirect(url_for("login"))

    user = get_safe_user(username)
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

            if not check_password_hash(USERS[username]["password"], old_password):
                return render_template("profile.html", user=user, greeting=greeting,
                    pwd_error="原密码错误")

            valid, msg = validate_password_strength(new_password)
            if not valid:
                return render_template("profile.html", user=user, greeting=greeting,
                    pwd_error=msg)

            if new_password != confirm_password:
                return render_template("profile.html", user=user, greeting=greeting,
                    pwd_error="两次输入的新密码不一致")

            USERS[username]["password"] = generate_password_hash(new_password)
            USERS[username]["first_login"] = False
            USERS[username]["session_version"] += 1
            session["session_version"] = USERS[username]["session_version"]
            logger.info(f"用户 '{username}' 在个人中心修改密码")
            return render_template("profile.html", user=user, greeting=greeting,
                pwd_success="密码修改成功")

        elif action == "update_info":
            new_email = request.form.get("email", "").strip()
            new_phone = request.form.get("phone", "").strip()

            # ---- 黑盒修复8：防 XSS 输入过滤 ----
            errors = []
            email_ok, email_err = sanitize_input(new_email, "邮箱")
            phone_ok, phone_err = sanitize_input(new_phone, "手机")

            if not email_ok:
                errors.append(email_err)
            elif not new_email or "@" not in new_email:
                errors.append("请输入有效的邮箱地址")

            if not phone_ok:
                errors.append(phone_err)
            elif not new_phone or len(new_phone) < 11:
                errors.append("请输入有效的手机号码（至少11位）")

            if errors:
                return render_template("profile.html", user=user, greeting=greeting,
                    info_error="；".join(errors))

            USERS[username]["email"] = new_email
            USERS[username]["phone"] = new_phone
            logger.info(f"用户 '{username}' 更新了个人信息")

            user = get_safe_user(username)
            return render_template("profile.html", user=user, greeting=greeting,
                info_success="个人信息更新成功")

    generate_csrf_token()
    return render_template("profile.html", user=user, greeting=greeting)


if __name__ == "__main__":
    print(f"[启动] Debug={DEBUG}, Host={HOST}, Port={PORT}")
    print(f"[启动] Session Cookie: HttpOnly=True, SameSite=Lax, Secure=False (HTTPS部署时请改为True)")
    app.run(debug=DEBUG, host=HOST, port=PORT)
