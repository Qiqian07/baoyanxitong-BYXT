"""生成演示数据。

运行：python seed.py

设计原则：
- 数据由评分引擎真实算出，不是写死的假数字。
- 主演示账号「黄俊键」的绩点/竞赛/论文经过精确设计，
  算出来的综合成绩与设计稿的 91.60 完全一致，
  这样打开页面就能看到「页面 = 设计稿」，同时证明引擎是对的。
- 随机数固定种子，每次初始化结果一致，方便答辩演示。
"""

import json
import os
import random
import sqlite3
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "baoyan.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")

YEAR = 2027                      # 推免年度
GRADE = 2023                     # 学生入学年级（2027 届）
TOTAL_STUDENTS = 146
CONFIRM_COUNT = 126              # 覆盖率 126/146 = 86.3%
QUOTA = 12                       # 保研名额
PASSWORD = "wt2026"              # 演示用统一初始密码
# 演示账号一律写 must_change_pwd = 0（视为已自行改密），避免每次演示都要先改密；
# 真实新建 / 批量导入的账号该字段为 1，登录后会被强制跳转改密页（app.py · change_password）。

random.seed(20261109)

SURNAMES = list("张李王刘陈杨黄赵吴周徐孙马朱胡林郭何高罗郑梁谢宋唐许韩冯邓曹彭曾")
GIVEN = ["子涵", "宇轩", "雨桐", "欣怡", "浩然", "思远", "嘉琪", "俊杰", "诗雅", "泽宇",
         "梓萱", "明轩", "佳怡", "俊键", "若曦", "天佑", "静怡", "博文", "雅静", "一鸣",
         "晨曦", "振宇", "文静", "立轩", "书瑶", "海涛", "舒涵", "皓宇", "梦琪", "子谦"]

MAJORS = [
    ("120201", "工商管理"),
    ("120203", "会计学"),
    ("120102", "信息管理与信息系统"),
    ("120202", "市场营销"),
    ("120601", "物流管理"),
]

COMP_NAMES = [
    "全国大学生电子商务“创新、创意及创业”挑战赛",
    "中国国际大学生创新大赛",
    "全国大学生市场调查与分析大赛",
    "全国大学生数学建模竞赛",
    "“挑战杯”全国大学生课外学术科技作品竞赛",
    "全国大学生物流设计大赛",
    "全国高校商业精英挑战赛",
]

PAPER_VENUES = {
    "A": ["管理世界", "南开管理评论", "管理科学学报"],
    "B": ["中国管理科学", "管理评论", "系统工程理论与实践"],
    "C": ["商业经济研究", "财会月刊", "物流技术"],
    "D": ["校级学报", "本科生学术论坛"],
}


def hash_pwd(raw):
    return generate_password_hash(raw, method="pbkdf2:sha256")


def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        db.executescript(f.read())

    now = datetime.now().replace(microsecond=0)
    freeze_at = (now + timedelta(days=2, hours=6)).strftime("%Y-%m-%d %H:%M")
    confirm_at = (now - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S")

    # ---------- 组织 ----------
    db.execute("INSERT INTO college (name, code) VALUES (?, ?)",
               ("管理学院", "WTU-SOM"))
    college_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    major_ids = []
    for code, name in MAJORS:
        db.execute("INSERT INTO major (college_id, name, code) VALUES (?, ?, ?)",
                   (college_id, name, code))
        major_ids.append(db.execute("SELECT last_insert_rowid()").fetchone()[0])

    # ---------- 账号：辅导员 / 管理员 ----------
    users = [
        ("T2001", "COUNSELOR", "周敏"),
        ("A1001", "COLLEGE_ADMIN", "李建国"),
        ("S1001", "SCHOOL_ADMIN", "王海"),
    ]
    for username, role, real_name in users:
        db.execute(
            "INSERT INTO sys_user (username, password_hash, role, real_name, must_change_pwd) "
            "VALUES (?, ?, ?, ?, 0)",
            (username, hash_pwd(PASSWORD), role, real_name),
        )

    counselor_id = db.execute("SELECT id FROM sys_user WHERE username='T2001'").fetchone()[0]

    # ---------- 班级 ----------
    class_ids = []
    for mi, (code, mname) in enumerate(MAJORS):
        for cn in (1, 2):
            db.execute(
                "INSERT INTO class_group (major_id, name, grade_year, counselor_id) "
                "VALUES (?, ?, ?, ?)",
                (major_ids[mi], f"{mname}{GRADE % 100}{cn:02d}", GRADE, counselor_id),
            )
            class_ids.append((major_ids[mi], mname,
                              db.execute("SELECT last_insert_rowid()").fetchone()[0]))

    # ---------- 评分规则（权重 85/8/7，与设计稿一致） ----------
    comp_coef = {
        "NATIONAL":   {"FIRST": 56, "SECOND": 48, "THIRD": 40},
        "PROVINCIAL": {"FIRST": 32, "SECOND": 26, "THIRD": 20},
        "SCHOOL":     {"FIRST": 16, "SECOND": 12, "THIRD": 8},
    }
    paper_coef = {"A": 95, "B": 86, "C": 75, "D": 60}
    db.execute(
        """INSERT INTO score_rule
           (year, version, gpa_weight, comp_weight, paper_weight, gpa_scale,
            comp_coef, paper_coef, comp_cap, paper_cap, status, effective_at, created_by)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (YEAR, "V1.0", 85.0, 8.0, 7.0, 5.0,
         json.dumps(comp_coef, ensure_ascii=False),
         json.dumps(paper_coef, ensure_ascii=False),
         100.0, 100.0, "ACTIVE", now.strftime("%Y-%m-%d %H:%M:%S"), None),
    )

    # ---------- 系统参数 ----------
    for key, value, remark in [
        ("quota_current", str(QUOTA), "本届保研名额"),
        ("freeze_at", freeze_at, "材料填报截止时间"),
        ("academic_year_label", "2026—2027 学年", "页面展示的学年"),
        ("current_year", str(YEAR), "当前推免年度"),
    ]:
        db.execute("INSERT INTO sys_config (key, value, remark) VALUES (?,?,?)",
                   (key, value, remark))

    # ---------- 学生 ----------
    used_names = set()
    students = []

    def next_name():
        while True:
            n = random.choice(SURNAMES) + random.choice(GIVEN)
            if n not in used_names:
                used_names.add(n)
                return n

    # 主演示账号固定信息
    main_name = "黄俊键"
    used_names.add(main_name)

    for i in range(TOTAL_STUDENTS):
        major_id, major_name, class_id = class_ids[i % len(class_ids)]
        if i == 0:
            name, student_no = main_name, f"{GRADE}010101"
        else:
            name = next_name()
            student_no = f"{GRADE}{i // len(class_ids) + 1:02d}{i % len(class_ids) + 1:02d}{i:03d}"

        db.execute(
            "INSERT INTO sys_user (username, password_hash, role, real_name, must_change_pwd) "
            "VALUES (?, ?, 'STUDENT', ?, 0)",
            (student_no, hash_pwd(PASSWORD), name),
        )
        user_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        # 绩点：前 13 名高绩点，主账号精确 4.62，其余随机
        if i == 0:
            gpa = 4.62
        elif i <= 13:
            gpa = round(random.uniform(4.75, 4.95), 2)
        else:
            gpa = round(random.uniform(3.05, 4.55), 2)

        db.execute(
            "INSERT INTO student (user_id, student_no, name, major_id, class_id, grade_year, "
            "gpa, gpa_scale, gpa_source, gpa_updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (user_id, student_no, name, major_id, class_id, GRADE, gpa, 5.0,
             "学生手工录入", now.strftime("%Y-%m-%d %H:%M:%S")),
        )
        student_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        students.append((student_id, name, student_no))

        # 竞赛与论文
        comps = []
        papers = []
        if i == 0:
            comps = [("NATIONAL", "FIRST", 1, COMP_NAMES[0]),
                     ("PROVINCIAL", "FIRST", 1, COMP_NAMES[2])]
            papers = [("B", 1)]
        elif i <= 13:
            comps = [("NATIONAL", "FIRST", 1, COMP_NAMES[i % len(COMP_NAMES)])]
            if i % 3 == 0:
                comps.append(("PROVINCIAL", "SECOND", 1, COMP_NAMES[(i + 2) % len(COMP_NAMES)]))
            papers = [("A" if i % 2 == 0 else "B", 1)]
        else:
            if random.random() < 0.45:
                comps.append((random.choice(["PROVINCIAL", "SCHOOL"]),
                              random.choice(["FIRST", "SECOND", "THIRD"]),
                              random.choice([1, 1, 2]), random.choice(COMP_NAMES)))
            if random.random() < 0.15:
                papers.append((random.choice(["C", "D"]), random.choice([1, 1, 2])))

        for level, award, rank, cname in comps:
            db.execute(
                "INSERT INTO competition (student_id, year, name, level, award, team_rank, "
                "award_date, status) VALUES (?,?,?,?,?,?,?, 'CONFIRMED')",
                (student_id, YEAR, cname, level, award, rank,
                 f"{YEAR - 1}-{random.randint(1, 12):02d}-15"),
            )
        for index_type, order in papers:
            db.execute(
                "INSERT INTO paper (student_id, year, title, venue, index_type, author_order, "
                "publish_date, status) VALUES (?,?,?,?,?,?,?, 'CONFIRMED')",
                (student_id, YEAR,
                 f"数字经济背景下企业运营效率研究（{random.randint(1, 9)}）",
                 random.choice(PAPER_VENUES[index_type]), index_type, order,
                 f"{YEAR - 1}-{random.randint(1, 12):02d}-20"),
            )

    # ---------- 参与状态：前 126 人确认参与 ----------
    for idx, (student_id, _, _) in enumerate(students):
        confirmed = idx < CONFIRM_COUNT
        db.execute(
            "INSERT INTO participation (student_id, year, status, confirmed_at) VALUES (?,?,?,?)",
            (student_id, YEAR, "CONFIRMED" if confirmed else "DRAFT",
             confirm_at if confirmed else None),
        )

    # ---------- 审计日志示例 ----------
    db.execute(
        "INSERT INTO audit_log (actor_id, actor_name, role, action, target_type, target_id, detail, ip) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (None, "李建国", "COLLEGE_ADMIN", "配置评分规则", "score_rule", str(YEAR),
         "创建 V1.0 评分规则：绩点 85% / 竞赛 8% / 论文 7%", "127.0.0.1"),
    )

    db.commit()
    db.close()

    print("演示数据已生成：instance/baoyan.db")
    print(f"  学生 {TOTAL_STUDENTS} 人，已确认参与 {CONFIRM_COUNT} 人")
    print("  登录账号（密码均为 %s）：" % PASSWORD)
    print("    学生  2023010101  黄俊键")
    print("    辅导员 T2001")
    print("    学院管理员 A1001")
    print("    学校管理员 S1001")


if __name__ == "__main__":
    main()
