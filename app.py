"""保研评估系统 · Web 应用入口

运行：
    python seed.py     # 第一次：生成演示数据
    python app.py      # 启动，浏览器打开 http://127.0.0.1:5000

演示账号（初始密码统一 wt2026，首次登录须改密）：
    学生      2023010101  黄俊键
    辅导员    T2001
    学院管理员 A1001
    学校管理员 S1001
"""

import csv
import functools
import hmac
import io
import json
import os
import secrets
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import (Flask, Response, abort, flash, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import db as database
import scoring
from db import get_db

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TS_FMT = "%Y-%m-%d %H:%M:%S"

# PRD 13 章「认证与账号」：30 分钟无操作超时、连续 5 次错误锁定 30 分钟、密码 ≥8 位含字母与数字
SESSION_IDLE_MINUTES = 30
MAX_LOGIN_FAILURES = 5
LOCK_MINUTES = 30
PASSWORD_MIN_LEN = 8

ROLE_LABEL = {
    "STUDENT": "学生",
    "COUNSELOR": "辅导员",
    "COLLEGE_ADMIN": "学院管理员",
    "SCHOOL_ADMIN": "学校管理员",
}


# ---------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------

def current_year(db):
    row = db.execute("SELECT value FROM sys_config WHERE key = 'current_year'").fetchone()
    return int(row["value"]) if row else 2027


def get_config(db, key, default=""):
    row = db.execute("SELECT value FROM sys_config WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def log_action(db, action, target_type=None, target_id=None, detail=None):
    """写审计日志。PRD 要求所有数据变动留痕，统一收敛到这一个函数。"""
    db.execute(
        "INSERT INTO audit_log (actor_id, actor_name, role, action, target_type, target_id, detail, ip) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (session.get("uid"), session.get("name"), session.get("role"),
         action, target_type, str(target_id) if target_id is not None else None,
         detail, request.remote_addr),
    )


def get_current_student(db):
    row = db.execute(
        """
        SELECT s.*, m.name AS major_name, c.name AS class_name
        FROM student s
        JOIN major m ON m.id = s.major_id
        LEFT JOIN class_group c ON c.id = s.class_id
        WHERE s.user_id = ?
        """,
        (session["uid"],),
    ).fetchone()
    if row is None:
        abort(403, "当前账号未绑定学生档案")
    return row


def get_participation(db, student_id, year):
    return db.execute(
        "SELECT * FROM participation WHERE student_id = ? AND year = ?",
        (student_id, year),
    ).fetchone()


def login_required(view):
    @functools.wraps(view)
    def wrapped(**kwargs):
        if "uid" not in session:
            return redirect(url_for("login", next=request.path))
        return view(**kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(**kwargs):
            if "uid" not in session:
                return redirect(url_for("login", next=request.path))
            if session.get("role") not in roles:
                abort(403)
            return view(**kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------
# 安全与校验小工具
# ---------------------------------------------------------------

def load_secret_key():
    """优先用环境变量；本地没有就生成一次并落到 instance/secret_key，避免进程重启后会话全失效。"""
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    path = os.path.join(BASE_DIR, "instance", "secret_key")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            saved = f.read().strip()
        if saved:
            return saved
    os.makedirs(os.path.dirname(path), exist_ok=True)
    generated = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as f:
        f.write(generated)
    print("[安全提示] 未设置 SECRET_KEY，已生成 instance/secret_key 供本地使用；"
          "部署到服务器前请改用环境变量（HANDOFF 第九节）。")
    return generated


def csrf_token():
    """为当前会话取（或生成）CSRF 令牌，模板里以隐藏域回传。"""
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def safe_next(target):
    """只允许站内相对路径，挡掉 //evil.com、http://evil.com 这类开放重定向。"""
    if not target:
        return url_for("home")
    if not target.startswith("/") or target.startswith("//") or "\\" in target:
        return url_for("home")
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return url_for("home")
    return target


def parse_ts(value):
    """解析库里存的本地时间字符串。"""
    if not value:
        return None
    for fmt in (TS_FMT, "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def validate_password(password, username="", old_password=""):
    """PRD 13 章口令规则。返回错误信息或 None。"""
    if not password:
        return "新密码不能为空"
    if len(password) < PASSWORD_MIN_LEN:
        return f"新密码至少 {PASSWORD_MIN_LEN} 位"
    if not any(ch.isalpha() for ch in password) or not any(ch.isdigit() for ch in password):
        return "新密码须同时包含字母与数字"
    if password == username:
        return "新密码不能与学号 / 工号相同"
    if old_password and password == old_password:
        return "新密码不能与当前密码相同"
    return None


def normalize_date(raw, label):
    """日期统一成 YYYY-MM-DD；空值允许（留空表示未填）。返回 (值, 错误信息)。"""
    text = (raw or "").strip()
    if not text:
        return "", None
    try:
        return datetime.strptime(text, "%Y-%m-%d").strftime("%Y-%m-%d"), None
    except ValueError:
        return None, f"{label}格式应为 YYYY-MM-DD，例如 2026-05-20"


def parse_rank(raw, allowed, label):
    """解析「本人第几位」这类序位字段，返回 (值, 错误信息)。

    不能用 request.form.get(..., type=int) or 1：转换失败会返回 None，
    再被 or 兜底成第 1 位，等于乱填反而拿到最高折算系数（1.0）。
    所以这里区分三种情况：留空、不是数字、超出范围，一律拒绝。
    """
    text = (raw or "").strip()
    if not text:
        return None, f"请选择{label}"
    try:
        value = int(text)
    except ValueError:
        return None, f"{label}须为 {min(allowed)}–{max(allowed)} 的数字"
    if value not in allowed:
        return None, f"{label}须为第 {min(allowed)}–{max(allowed)} 位（第 {max(allowed)} 位及以后按第 {max(allowed)} 位折算）"
    return value, None


def csv_safe(value):
    """挡住 CSV 公式注入：以 = + - @ 或制表符开头的单元格前面补单引号。"""
    if value is None:
        return ""
    text = str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


# ---------------------------------------------------------------
# 应用工厂
# ---------------------------------------------------------------

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = load_secret_key()
    app.config["JSON_AS_ASCII"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=SESSION_IDLE_MINUTES)
    database.register(app)

    @app.before_request
    def guard_request():
        # 静态资源不参与会话校验，否则超时后页面样式/脚本会 302 成 HTML
        if request.endpoint == "static":
            return None

        # 1）CSRF：所有写操作必须带本会话的令牌（PRD 13 / 测试报告 P2-3）
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            expected = session.get("_csrf")
            if not expected or not sent or not hmac.compare_digest(expected, sent):
                abort(400, "表单已过期或来源校验失败，请刷新页面后重新提交")

        # 2）会话空闲超时（PRD 13：30 分钟无操作）
        if session.get("uid"):
            last_seen = session.get("_seen_at")
            now_ts = time.time()
            if last_seen and now_ts - last_seen > SESSION_IDLE_MINUTES * 60:
                session.clear()
                flash("登录状态已超时（30 分钟无操作），请重新登录", "error")
                return redirect(url_for("login"))
            session["_seen_at"] = now_ts

        # 3）首次登录强制改密（schema.must_change_pwd，PRD 13）
        if session.get("uid") and session.get("must_change_pwd"):
            if request.endpoint not in ("change_password", "logout", "static"):
                return redirect(url_for("change_password"))

    @app.context_processor
    def inject_globals():
        return {
            "role_label": ROLE_LABEL,
            "csrf_token": csrf_token(),
            "current_user": {
                "name": session.get("name"),
                "role": session.get("role"),
                "role_label": ROLE_LABEL.get(session.get("role", ""), ""),
            },
        }

    # ---------- 认证 ----------

    @app.route("/", methods=["GET"])
    def index():
        if "uid" in session:
            return redirect(url_for("home"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("account", "").strip()
            password = request.form.get("password", "")
            db = get_db()
            user = db.execute(
                "SELECT * FROM sys_user WHERE username = ?", (username,)
            ).fetchone()

            now = datetime.now()

            # 锁定中直接拒绝，不给逐次试探的机会（PRD 13：连续 5 次错误锁定 30 分钟）
            if user is not None:
                locked_until = parse_ts(user["locked_until"])
                if locked_until and locked_until > now:
                    minutes = int((locked_until - now).total_seconds() // 60) + 1
                    flash(f"密码连续输错 {MAX_LOGIN_FAILURES} 次，账号已锁定，请 {minutes} 分钟后再试", "error")
                    return render_template("login.html", account=username), 429

            if user is None or not check_password_hash(user["password_hash"], password):
                if user is not None:
                    fails = (user["failed_attempts"] or 0) + 1
                    if fails >= MAX_LOGIN_FAILURES:
                        db.execute(
                            "UPDATE sys_user SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                            ((now + timedelta(minutes=LOCK_MINUTES)).strftime(TS_FMT), user["id"]),
                        )
                        log_action(db, "账号锁定", "sys_user", user["id"],
                                   f"连续 {MAX_LOGIN_FAILURES} 次密码错误，锁定 {LOCK_MINUTES} 分钟")
                        db.commit()
                        flash(f"密码连续错误 {MAX_LOGIN_FAILURES} 次，账号已锁定 {LOCK_MINUTES} 分钟", "error")
                        return render_template("login.html", account=username), 429
                    db.execute("UPDATE sys_user SET failed_attempts = ? WHERE id = ?",
                               (fails, user["id"]))
                    log_action(db, "登录失败", "sys_user", user["id"],
                               f"账号 {username} 密码错误（第 {fails} 次）")
                    db.commit()
                    flash(f"账号或密码不正确，请重新输入（连续错误 {MAX_LOGIN_FAILURES} 次将锁定账号）", "error")
                else:
                    flash("账号或密码不正确，请重新输入", "error")
                return render_template("login.html", account=username), 401

            if user["status"] != 1:
                flash("该账号已停用，请联系学院管理员", "error")
                return render_template("login.html", account=username), 403

            session.clear()
            session["uid"] = user["id"]
            session["role"] = user["role"]
            session["name"] = user["real_name"]
            session["must_change_pwd"] = 1 if user["must_change_pwd"] else 0
            session.permanent = True
            session["_seen_at"] = time.time()
            csrf_token()   # 登录成功后重发令牌，避免沿用登录前的会话标识

            db.execute(
                "UPDATE sys_user SET last_login_at = ?, failed_attempts = 0, locked_until = NULL "
                "WHERE id = ?",
                (now.strftime(TS_FMT), user["id"]),
            )
            log_action(db, "登录系统", "sys_user", user["id"])
            db.commit()

            if session["must_change_pwd"]:
                flash("首次登录请先修改初始密码后再使用系统", "info")
                return redirect(url_for("change_password"))
            return redirect(safe_next(request.args.get("next")))

        if "uid" in session:
            return redirect(url_for("home"))
        return render_template("login.html", account="")

    @app.route("/account/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        """首次登录强制改密 / 主动修改密码（PRD 13）。"""
        db = get_db()
        user = db.execute("SELECT * FROM sys_user WHERE id = ?", (session["uid"],)).fetchone()
        if user is None:
            session.clear()
            abort(403, "账号不存在")
        forced = bool(user["must_change_pwd"])

        if request.method == "POST":
            old_password = request.form.get("old_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not check_password_hash(user["password_hash"], old_password):
                flash("当前密码不正确", "error")
                return render_template("account/password.html", forced=forced), 400
            err = validate_password(new_password, user["username"], old_password)
            if err:
                flash(err, "error")
                return render_template("account/password.html", forced=forced), 400
            if new_password != confirm_password:
                flash("两次输入的新密码不一致", "error")
                return render_template("account/password.html", forced=forced), 400

            db.execute(
                "UPDATE sys_user SET password_hash = ?, must_change_pwd = 0 WHERE id = ?",
                (generate_password_hash(new_password, method="pbkdf2:sha256"), user["id"]),
            )
            log_action(db, "修改密码", "sys_user", user["id"],
                       "首次登录改密" if forced else "主动修改")
            db.commit()
            session["must_change_pwd"] = 0
            flash("密码已更新", "success")
            return redirect(url_for("home"))

        return render_template("account/password.html", forced=forced)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/home")
    @login_required
    def home():
        role = session.get("role")
        if role == "STUDENT":
            return redirect(url_for("student_scores"))
        if role == "COUNSELOR":
            return redirect(url_for("counselor_students"))
        return redirect(url_for("admin_rules"))

    # ---------- 学生端 ----------

    @app.route("/student/scores")
    @role_required("STUDENT")
    def student_scores():
        db = get_db()
        year = current_year(db)
        stu = get_current_student(db)
        part = get_participation(db, stu["id"], year)
        ranking = scoring.build_ranking(db, year)
        quota = scoring.get_quota(db)
        cutoff = scoring.cutoff_score(ranking, quota)

        me = next((r for r in ranking["rows"] if r["student_id"] == stu["id"]), None)
        gap = None
        if me and cutoff is not None:
            gap = scoring.round2(me["total"] - cutoff)

        return render_template(
            "student/scores.html",
            year=year,
            stu=stu,
            part=part,
            me=me,
            rule=ranking["rule"],
            stats=ranking["stats"],
            quota=quota,
            cutoff=cutoff,
            gap=gap,
            freeze_at=get_config(db, "freeze_at"),
            year_label=get_config(db, "academic_year_label"),
        )

    @app.route("/student/ranking")
    @role_required("STUDENT")
    def student_ranking():
        db = get_db()
        year = current_year(db)
        stu = get_current_student(db)
        ranking = scoring.build_ranking(db, year)
        quota = scoring.get_quota(db)
        majors = db.execute("SELECT id, name FROM major WHERE is_active = 1 ORDER BY id").fetchall()

        major_id = request.args.get("major", type=int)
        me = next((r for r in ranking["rows"] if r["student_id"] == stu["id"]), None)

        # PRD 8.1 / 验收标准②：学生仅见本人名次与参与排名总人数，
        # 接口不得返回其他学生的姓名、学号或分数。
        # 默认 strict 只下发本人一行；学院确需公示完整榜单时，
        # 由管理员把 sys_config.student_ranking_scope 改为 full。
        scope = get_config(db, "student_ranking_scope", "strict")
        if scope == "full":
            rows = ranking["rows"]
            if major_id:
                rows = [r for r in rows if r["major_id"] == major_id]
        else:
            rows = [me] if me else []

        cutoff = scoring.cutoff_score(ranking, quota)
        gap = scoring.round2(me["total"] - cutoff) if (me and cutoff is not None) else None

        return render_template(
            "student/ranking.html",
            year=year,
            stu=stu,
            rows=rows,
            me=me,
            scope=scope,
            gap=gap,
            majors=majors,
            selected_major=major_id,
            quota=quota,
            cutoff=cutoff,
            stats=ranking["stats"],
            freeze_at=get_config(db, "freeze_at"),
            year_label=get_config(db, "academic_year_label"),
        )

    @app.route("/student/entry")
    @role_required("STUDENT")
    def student_entry():
        db = get_db()
        year = current_year(db)
        stu = get_current_student(db)
        part = get_participation(db, stu["id"], year)
        comps = db.execute(
            "SELECT * FROM competition WHERE student_id = ? AND year = ? ORDER BY id",
            (stu["id"], year)).fetchall()
        papers = db.execute(
            "SELECT * FROM paper WHERE student_id = ? AND year = ? ORDER BY id",
            (stu["id"], year)).fetchall()
        rule = scoring.load_rule(db, year)

        locked = part is not None and part["status"] == "CONFIRMED"
        return render_template(
            "student/entry.html",
            year=year, stu=stu, part=part, comps=comps, papers=papers,
            rule=rule, locked=locked,
            freeze_at=get_config(db, "freeze_at"),
            level_label=scoring.LEVEL_LABEL,
            award_label=scoring.AWARD_LABEL,
            index_label=scoring.INDEX_LABEL,
            # 折算系数从 scoring 取，不在模板里写死，避免改规则后页面算分与实际不一致
            team_factor=scoring.TEAM_RANK_FACTOR,
            author_factor=scoring.AUTHOR_ORDER_FACTOR,
        )

    @app.route("/student/gpa", methods=["POST"])
    @role_required("STUDENT")
    def update_gpa():
        db = get_db()
        year = current_year(db)
        stu = get_current_student(db)
        part = get_participation(db, stu["id"], year)
        if part and part["status"] == "CONFIRMED":
            flash("已确认参与，绩点不可再修改。如需变更请先撤回。", "error")
            return redirect(url_for("student_entry"))

        raw = request.form.get("gpa", "").strip()
        try:
            gpa = float(raw)
        except ValueError:
            flash("绩点必须是数字，例如 4.62", "error")
            return redirect(url_for("student_entry"))
        if not (0 <= gpa <= 5.0):
            flash("绩点取值范围为 0–5.00，请检查后重新填写", "error")
            return redirect(url_for("student_entry"))

        # 统一走 scoring.round2（Decimal + ROUND_HALF_UP），不用内置 round()，
        # 否则 4.625 会存成 4.62，与项目规范和数据准确性要求不符
        gpa_value = scoring.round2(gpa)

        before = stu["gpa"]
        db.execute(
            "UPDATE student SET gpa = ?, gpa_updated_at = ? WHERE id = ?",
            (gpa_value, datetime.now().strftime(TS_FMT), stu["id"]),
        )
        log_action(db, "修改绩点", "student", stu["id"], f"{before} → {gpa_value}")
        db.commit()
        flash("绩点已保存", "success")
        return redirect(url_for("student_entry"))

    @app.route("/student/competition/add", methods=["POST"])
    @role_required("STUDENT")
    def add_competition():
        db = get_db()
        year = current_year(db)
        stu = get_current_student(db)
        part = get_participation(db, stu["id"], year)
        if part and part["status"] == "CONFIRMED":
            flash("已确认参与，数据不可再修改", "error")
            return redirect(url_for("student_entry"))

        name = request.form.get("name", "").strip()
        level = request.form.get("level", "")
        award = request.form.get("award", "")
        if not name or level not in scoring.LEVEL_LABEL or award not in scoring.AWARD_LABEL:
            flash("竞赛名称、级别、获奖等级均为必填项", "error")
            return redirect(url_for("student_entry"))

        team_rank, rank_err = parse_rank(
            request.form.get("team_rank"), scoring.TEAM_RANK_FACTOR, "本人排名")
        if rank_err:
            flash(rank_err, "error")
            return redirect(url_for("student_entry"))

        award_date, date_err = normalize_date(request.form.get("award_date"), "获奖时间")
        if date_err:
            flash(date_err, "error")
            return redirect(url_for("student_entry"))

        db.execute(
            "INSERT INTO competition (student_id, year, name, level, award, team_rank, award_date, status) "
            "VALUES (?,?,?,?,?,?,?, 'DRAFT')",
            (stu["id"], year, name, level, award, team_rank, award_date),
        )
        log_action(db, "新增竞赛", "competition", None, name)
        db.commit()
        flash("竞赛记录已添加", "success")
        return redirect(url_for("student_entry"))

    @app.route("/student/competition/<int:cid>/delete", methods=["POST"])
    @role_required("STUDENT")
    def delete_competition(cid):
        db = get_db()
        year = current_year(db)
        stu = get_current_student(db)
        row = db.execute("SELECT * FROM competition WHERE id = ? AND student_id = ?",
                         (cid, stu["id"])).fetchone()
        if row is None:
            abort(404)

        # PRD 8.2：已提交、已通过及冻结后的数据不可删除，仅草稿可删。
        # 页面上锁定态的删除按钮不渲染，但接口必须自己拦——
        # 否则构造一个 POST 就能绕过界面删掉已计入排名的数据。
        part = get_participation(db, stu["id"], year)
        if part and part["status"] == "CONFIRMED":
            flash("已确认参与，数据不可删除。如需修改请先撤回。", "error")
            return redirect(url_for("student_entry"))
        if row["status"] != "DRAFT":
            flash("该条记录已提交，不可删除。", "error")
            return redirect(url_for("student_entry"))

        db.execute("DELETE FROM competition WHERE id = ?", (cid,))
        log_action(db, "删除竞赛", "competition", cid, row["name"])
        db.commit()
        flash("竞赛记录已删除", "success")
        return redirect(url_for("student_entry"))

    @app.route("/student/paper/add", methods=["POST"])
    @role_required("STUDENT")
    def add_paper():
        db = get_db()
        year = current_year(db)
        stu = get_current_student(db)
        part = get_participation(db, stu["id"], year)
        if part and part["status"] == "CONFIRMED":
            flash("已确认参与，数据不可再修改", "error")
            return redirect(url_for("student_entry"))

        title = request.form.get("title", "").strip()
        index_type = request.form.get("index_type", "")
        if not title or index_type not in scoring.INDEX_LABEL:
            flash("论文标题与收录类型为必填项", "error")
            return redirect(url_for("student_entry"))

        author_order, rank_err = parse_rank(
            request.form.get("author_order"), scoring.AUTHOR_ORDER_FACTOR, "作者排序")
        if rank_err:
            flash(rank_err, "error")
            return redirect(url_for("student_entry"))

        publish_date, date_err = normalize_date(request.form.get("publish_date"), "发表时间")
        if date_err:
            flash(date_err, "error")
            return redirect(url_for("student_entry"))

        db.execute(
            "INSERT INTO paper (student_id, year, title, venue, index_type, author_order, "
            "publish_date, status) VALUES (?,?,?,?,?,?,?, 'DRAFT')",
            (stu["id"], year, title, request.form.get("venue", ""), index_type,
             author_order, publish_date),
        )
        log_action(db, "新增论文", "paper", None, title)
        db.commit()
        flash("论文记录已添加", "success")
        return redirect(url_for("student_entry"))

    @app.route("/student/paper/<int:pid>/delete", methods=["POST"])
    @role_required("STUDENT")
    def delete_paper(pid):
        db = get_db()
        year = current_year(db)
        stu = get_current_student(db)
        row = db.execute("SELECT * FROM paper WHERE id = ? AND student_id = ?",
                         (pid, stu["id"])).fetchone()
        if row is None:
            abort(404)

        # 同 delete_competition：草稿才可删，锁定态一律拒绝（PRD 8.2）
        part = get_participation(db, stu["id"], year)
        if part and part["status"] == "CONFIRMED":
            flash("已确认参与，数据不可删除。如需修改请先撤回。", "error")
            return redirect(url_for("student_entry"))
        if row["status"] != "DRAFT":
            flash("该条记录已提交，不可删除。", "error")
            return redirect(url_for("student_entry"))

        db.execute("DELETE FROM paper WHERE id = ?", (pid,))
        log_action(db, "删除论文", "paper", pid, row["title"])
        db.commit()
        flash("论文记录已删除", "success")
        return redirect(url_for("student_entry"))

    @app.route("/student/confirm", methods=["POST"])
    @role_required("STUDENT")
    def confirm_participation():
        """确认参与：锁定数据，进入预估排名（PRD S-04，V1.0 口径）。"""
        db = get_db()
        year = current_year(db)
        stu = get_current_student(db)
        part = get_participation(db, stu["id"], year)

        if part and part["status"] == "CONFIRMED":
            flash("已经确认参与，无需重复操作", "info")
            return redirect(url_for("student_scores"))
        if not stu["gpa"]:
            flash("请先填写绩点后再确认参与", "error")
            return redirect(url_for("student_entry"))

        now = datetime.now().strftime(TS_FMT)
        if part:
            db.execute(
                "UPDATE participation SET status = 'CONFIRMED', confirmed_at = ? WHERE id = ?",
                (now, part["id"]))
        else:
            db.execute(
                "INSERT INTO participation (student_id, year, status, confirmed_at) VALUES (?,?,?,?)",
                (stu["id"], year, "CONFIRMED", now))
        # 明细同步转为已确认，进入排名口径
        db.execute("UPDATE competition SET status = 'CONFIRMED' WHERE student_id = ? AND year = ?",
                   (stu["id"], year))
        db.execute("UPDATE paper SET status = 'CONFIRMED' WHERE student_id = ? AND year = ?",
                   (stu["id"], year))
        log_action(db, "确认参与", "participation", stu["id"])
        db.commit()
        flash("已确认参与，数据已锁定并计入预估排名", "success")
        return redirect(url_for("student_scores"))

    @app.route("/student/withdraw", methods=["POST"])
    @role_required("STUDENT")
    def withdraw_participation():
        db = get_db()
        year = current_year(db)
        stu = get_current_student(db)
        part = get_participation(db, stu["id"], year)
        if not part or part["status"] != "CONFIRMED":
            flash("当前没有可撤回的确认", "error")
            return redirect(url_for("student_scores"))

        db.execute("UPDATE participation SET status = 'DRAFT', confirmed_at = NULL WHERE id = ?",
                   (part["id"],))
        db.execute("UPDATE competition SET status = 'DRAFT' WHERE student_id = ? AND year = ?",
                   (stu["id"], year))
        db.execute("UPDATE paper SET status = 'DRAFT' WHERE student_id = ? AND year = ?",
                   (stu["id"], year))
        log_action(db, "撤回确认", "participation", stu["id"])
        db.commit()
        flash("已撤回，数据恢复为草稿可编辑，暂不计入排名", "success")
        return redirect(url_for("student_entry"))

    # ---------- 辅导员端 ----------

    @app.route("/counselor/students")
    @role_required("COUNSELOR", "COLLEGE_ADMIN", "SCHOOL_ADMIN")
    def counselor_students():
        db = get_db()
        year = current_year(db)
        ranking = scoring.build_ranking(db, year)
        quota = scoring.get_quota(db)
        return render_template(
            "counselor/students.html",
            year=year,
            rows=ranking["rows"],
            stats=ranking["stats"],
            quota=quota,
            cutoff=scoring.cutoff_score(ranking, quota),
            year_label=get_config(db, "academic_year_label"),
        )

    @app.route("/counselor/export.csv")
    @role_required("COUNSELOR", "COLLEGE_ADMIN", "SCHOOL_ADMIN")
    def counselor_export():
        """导出排名名单（CSV，带 BOM 保证 Excel 打开中文不乱码）。"""
        db = get_db()
        year = current_year(db)
        ranking = scoring.build_ranking(db, year)

        buf = io.StringIO()
        buf.write("\ufeff")
        writer = csv.writer(buf)
        writer.writerow(["顺位", "姓名", "学号", "专业", "班级",
                         "绩点", "绩点折算", "竞赛折算", "论文折算", "综合成绩"])
        for r in ranking["rows"]:
            writer.writerow([r["rank_college"], csv_safe(r["name"]), csv_safe(r["student_no"]),
                             csv_safe(r["major_name"]), csv_safe(r["class_name"] or ""),
                             r["gpa"], r["gpa_score"], r["comp_score"],
                             r["paper_score"], r["total"]])

        log_action(db, "导出排名名单", "ranking", year,
                   f"共 {len(ranking['rows'])} 条")
        db.commit()

        filename = f"ranking_{year}.csv"
        return Response(
            buf.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    # ---------- 管理员端 ----------

    @app.route("/admin/rules", methods=["GET", "POST"])
    @role_required("COLLEGE_ADMIN", "SCHOOL_ADMIN")
    def admin_rules():
        db = get_db()
        year = current_year(db)

        if request.method == "POST":
            try:
                gpa_w = float(request.form.get("gpa_weight", 0))
                comp_w = float(request.form.get("comp_weight", 0))
                paper_w = float(request.form.get("paper_weight", 0))
            except ValueError:
                flash("权重必须是数字", "error")
                return redirect(url_for("admin_rules"))

            err = scoring.validate_rule(gpa_w, comp_w, paper_w)
            if err:
                flash(err, "error")
                return redirect(url_for("admin_rules"))

            old = scoring.load_rule(db, year)
            # 历史版本只改状态，不覆盖其权重——否则「历史版本可查、可对比」就失效了
            db.execute("UPDATE score_rule SET status = 'ARCHIVED' WHERE id = ?", (old["id"],))
            db.execute(
                """INSERT INTO score_rule
                   (year, version, gpa_weight, comp_weight, paper_weight, gpa_scale,
                    comp_coef, paper_coef, comp_cap, paper_cap, status, effective_at, created_by)
                   VALUES (?,?,?,?,?,?,?,?,?,?,'ACTIVE',?,?)""",
                (year, f"{old['version']}-r{datetime.now():%m%d%H%M}",
                 gpa_w, comp_w, paper_w, old["gpa_scale"],
                 json.dumps(old["comp_coef"], ensure_ascii=False),
                 json.dumps(old["paper_coef"], ensure_ascii=False),
                 old["comp_cap"], old["paper_cap"],
                 datetime.now().strftime(TS_FMT), session.get("uid")),
            )
            log_action(db, "修改评分权重", "score_rule", year,
                       f"{old['gpa_weight']}/{old['comp_weight']}/{old['paper_weight']} → "
                       f"{gpa_w}/{comp_w}/{paper_w}")
            db.commit()
            flash("评分规则已保存，排名已按新权重重算", "success")
            return redirect(url_for("admin_rules"))

        rule = scoring.load_rule(db, year)
        history = db.execute(
            "SELECT * FROM score_rule WHERE year = ? ORDER BY id DESC", (year,)
        ).fetchall()
        ranking = scoring.build_ranking(db, year)
        return render_template(
            "admin/rules.html",
            year=year, rule=rule, history=history,
            stats=ranking["stats"],
            top=ranking["rows"][:5],
            quota=scoring.get_quota(db),
            cutoff=scoring.cutoff_score(ranking, scoring.get_quota(db)),
            year_label=get_config(db, "academic_year_label"),
        )

    # ---------- 错误页 ----------

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", code=400,
                               message=getattr(e, "description", "请求参数不正确")), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403, message="你没有权限访问这个页面"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404,
                               message="页面不存在，或这条数据不属于你"), 404

    return app


app = create_app()

if __name__ == "__main__":
    print("=" * 56)
    print("  保研评估系统  ·  武汉纺织大学管理学院")
    print("  打开浏览器访问：http://127.0.0.1:5000")
    print("  学生 2023010101 / 辅导员 T2001 / 管理员 A1001")
    print("  初始密码：wt2026（首次登录须修改）")
    print("=" * 56)
    # debug 由环境变量控制，默认关闭；需要调试时 set FLASK_DEBUG=1
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1",
            port=int(os.environ.get("PORT", "5000")))
