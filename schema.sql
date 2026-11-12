-- =========================================================
-- 武汉纺织大学管理学院 · 保研评估系统
-- V1.0 排名计算引擎 数据库结构（SQLite）
-- 说明：
--   1. 评分权重与换算系数不写死在代码里，全部存在 score_rule 表，按届生效。
--   2. 所有状态字段用 TEXT + CHECK 约束，SQLite 无原生 ENUM。
--   3. 时间统一存 TEXT（ISO8601，Asia/Shanghai 本地时间）。
-- =========================================================

PRAGMA foreign_keys = ON;

-- ---------- 组织 ----------

CREATE TABLE IF NOT EXISTS college (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    code        TEXT
);

CREATE TABLE IF NOT EXISTS major (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    college_id  INTEGER NOT NULL REFERENCES college(id),
    name        TEXT NOT NULL,
    code        TEXT,
    is_active   INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS class_group (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    major_id     INTEGER NOT NULL REFERENCES major(id),
    name         TEXT NOT NULL,
    grade_year   INTEGER NOT NULL,
    counselor_id INTEGER REFERENCES sys_user(id)
);

-- ---------- 账号 ----------

CREATE TABLE IF NOT EXISTS sys_user (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,          -- 学号 / 工号
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('STUDENT','COUNSELOR','COLLEGE_ADMIN','SCHOOL_ADMIN')),
    real_name       TEXT NOT NULL,
    status          INTEGER NOT NULL DEFAULT 1,    -- 1 正常 0 停用
    must_change_pwd INTEGER NOT NULL DEFAULT 1,    -- 首次登录强制改密（PRD 13 章）
    failed_attempts INTEGER NOT NULL DEFAULT 0,    -- 连续登录失败次数（5 次锁定 30 分钟，PRD 13 章）
    locked_until    TEXT,                          -- 锁定到期时间，空表示未锁定
    last_login_at   TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS student (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER NOT NULL UNIQUE REFERENCES sys_user(id),
    student_no        TEXT NOT NULL UNIQUE,
    name              TEXT NOT NULL,
    major_id          INTEGER NOT NULL REFERENCES major(id),
    class_id          INTEGER REFERENCES class_group(id),
    grade_year        INTEGER,
    enrollment_status TEXT NOT NULL DEFAULT 'ACTIVE'
                      CHECK (enrollment_status IN ('ACTIVE','SUSPENDED','LEFT','GRADUATED')),
    -- 绩点由学生手工录入（V1.0–V1.2 不对接教务系统，见 PRD 4.2）
    gpa               REAL NOT NULL DEFAULT 0,
    gpa_scale         REAL NOT NULL DEFAULT 5.0,
    gpa_source        TEXT,
    gpa_updated_at    TEXT
);

-- ---------- 学生数据 ----------

CREATE TABLE IF NOT EXISTS competition (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id  INTEGER NOT NULL REFERENCES student(id),
    year        INTEGER NOT NULL,
    name        TEXT NOT NULL,
    level       TEXT NOT NULL CHECK (level IN ('NATIONAL','PROVINCIAL','SCHOOL')),
    award       TEXT NOT NULL CHECK (award IN ('FIRST','SECOND','THIRD')),
    team_rank   INTEGER NOT NULL DEFAULT 1,        -- 本人排名（参与者第几位）
    award_date  TEXT,
    status      TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','CONFIRMED')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at  TEXT
);

CREATE TABLE IF NOT EXISTS paper (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id   INTEGER NOT NULL REFERENCES student(id),
    year         INTEGER NOT NULL,
    title        TEXT NOT NULL,
    venue        TEXT,                             -- 期刊 / 会议名
    index_type   TEXT NOT NULL CHECK (index_type IN ('A','B','C','D')),
    author_order INTEGER NOT NULL DEFAULT 1,
    publish_date TEXT,
    status       TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','CONFIRMED')),
    created_at   TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at   TEXT
);

-- 参与状态：V1.0 用「确认参与」，确认后数据锁定并进入预估排名
CREATE TABLE IF NOT EXISTS participation (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id   INTEGER NOT NULL REFERENCES student(id),
    year         INTEGER NOT NULL,
    status       TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','CONFIRMED','WITHDRAWN')),
    confirmed_at TEXT,
    UNIQUE (student_id, year)
);

-- ---------- 评分规则 ----------

CREATE TABLE IF NOT EXISTS score_rule (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    year         INTEGER NOT NULL,
    version      TEXT NOT NULL,                    -- 如 V1.0
    gpa_weight   REAL NOT NULL,
    comp_weight  REAL NOT NULL,
    paper_weight REAL NOT NULL,
    gpa_scale    REAL NOT NULL DEFAULT 5.0,
    comp_coef    TEXT NOT NULL,                    -- JSON：级别×奖项 系数
    paper_coef   TEXT NOT NULL,                    -- JSON：分区 基准分
    comp_cap     REAL NOT NULL DEFAULT 100,
    paper_cap    REAL NOT NULL DEFAULT 100,
    status       TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','ARCHIVED')),
    effective_at TEXT NOT NULL,
    created_by   INTEGER,
    created_at   TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE (year, version)
);

-- ---------- 审计 ----------

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id    INTEGER,
    actor_name  TEXT,
    role        TEXT,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    detail      TEXT,
    ip          TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- ---------- 系统参数 ----------

CREATE TABLE IF NOT EXISTS sys_config (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL,
    remark TEXT
);

CREATE INDEX IF NOT EXISTS idx_student_major ON student(major_id);
CREATE INDEX IF NOT EXISTS idx_competition_student ON competition(student_id, year);
CREATE INDEX IF NOT EXISTS idx_paper_student ON paper(student_id, year);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
