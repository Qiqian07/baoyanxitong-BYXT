"""评分与排名计算引擎 —— 整个系统的心脏。

核心公式：
    综合成绩 = 绩点折算 × 绩点权重 + 竞赛折算 × 竞赛权重 + 论文折算 × 论文权重

设计要点：
1. 所有权重和系数从 score_rule 表读取，代码里没有任何魔法数字。
   管理员改规则 → 重算 → 排名变化，不需要改一行代码。
2. 所有分数统一保留两位小数，采用四舍五入（ROUND_HALF_UP），
   不用 Python 内置 round()，因为它是银行家舍入（2.5 → 2），
   学生和辅导员核对时会认为算错了。
3. 同分处理：总分相同 → 名次并列，后续名次顺延（1、1、3）。
   展示顺序用单项折算分做 tie-break，但不影响并列名次。
"""

import json
from decimal import Decimal, ROUND_HALF_UP

# 团队排名折算系数：本人是第几作者 / 第几位参赛者（第 4 位及以后同 0.3）
TEAM_RANK_FACTOR = {1: 1.0, 2: 0.7, 3: 0.5, 4: 0.3}
TEAM_RANK_DEFAULT = 0.3

# 论文作者排序折算系数（第 4 位及以后同 0.2）
AUTHOR_ORDER_FACTOR = {1: 1.0, 2: 0.6, 3: 0.4, 4: 0.2}
AUTHOR_ORDER_DEFAULT = 0.2

LEVEL_LABEL = {"NATIONAL": "国家级", "PROVINCIAL": "省级", "SCHOOL": "校级"}
AWARD_LABEL = {"FIRST": "一等奖", "SECOND": "二等奖", "THIRD": "三等奖"}
INDEX_LABEL = {"A": "A 类", "B": "B 类", "C": "C 类", "D": "D 类"}


def _d(value):
    """把 float 安全转成 Decimal（先转字符串，避免 0.1 精度噪声）。"""
    return Decimal(str(value))


def round2(value):
    """四舍五入保留两位小数，返回 float。"""
    return float(_d(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def mask_name(name):
    """姓名打码：黄*键 / 李*。榜单展示用，避免泄露完整身份。"""
    if not name:
        return ""
    if len(name) <= 2:
        return name[0] + "*"
    return name[0] + "*" * (len(name) - 2) + name[-1]


# ---------------------------------------------------------------
# 规则读取
# ---------------------------------------------------------------

def load_rule(db, year):
    """读取该年度生效的评分规则；没有就抛错，绝不静默用默认值。"""
    row = db.execute(
        "SELECT * FROM score_rule WHERE year = ? AND status = 'ACTIVE' "
        "ORDER BY id DESC LIMIT 1",
        (year,),
    ).fetchone()
    if row is None:
        raise LookupError(f"{year} 年度尚未配置评分规则，请先由学院管理员配置")
    return {
        "id": row["id"],
        "year": row["year"],
        "version": row["version"],
        "gpa_weight": row["gpa_weight"],
        "comp_weight": row["comp_weight"],
        "paper_weight": row["paper_weight"],
        "gpa_scale": row["gpa_scale"],
        "comp_coef": json.loads(row["comp_coef"]),
        "paper_coef": json.loads(row["paper_coef"]),
        "comp_cap": row["comp_cap"],
        "paper_cap": row["paper_cap"],
    }


def validate_rule(gpa_w, comp_w, paper_w):
    """校验权重：必须非负、单项不超过 100 且合计 100。返回错误信息或 None。"""
    for name, w in (("绩点", gpa_w), ("竞赛", comp_w), ("论文", paper_w)):
        if w is None or w < 0:
            return f"{name}权重不能为负数"
        if w > 100:
            return f"{name}权重不能超过 100%"
    if round2(_d(gpa_w) + _d(comp_w) + _d(paper_w)) != 100.00:
        return f"三项权重合计必须为 100%，当前为 {round2(_d(gpa_w) + _d(comp_w) + _d(paper_w))}%"
    return None


# ---------------------------------------------------------------
# 单项折算
# ---------------------------------------------------------------

def calc_gpa_score(gpa, scale=5.0):
    """绩点折算到百分制：4.62 / 5.00 × 100 = 92.40。"""
    if not gpa or not scale:
        return 0.0
    score = _d(gpa) / _d(scale) * 100
    return round2(min(max(score, Decimal("0")), Decimal("100")))


def calc_competition_score(items, coef, cap=100.0):
    """竞赛折算分：各条按「级别 × 奖项 × 本人排名」查系数后累加，封顶 100。"""
    total = Decimal("0")
    for it in items:
        base = coef.get(it["level"], {}).get(it["award"], 0)
        factor = TEAM_RANK_FACTOR.get(it["team_rank"], TEAM_RANK_DEFAULT)
        total += _d(base) * _d(factor)
    cap_d = _d(cap)
    if total > cap_d:
        total = cap_d
    return round2(total)


def calc_paper_score(items, coef, cap=100.0):
    """论文折算分：各篇按「分区 × 作者排序」查系数后累加，封顶 100。"""
    total = Decimal("0")
    for it in items:
        base = coef.get(it["index_type"], 0)
        factor = AUTHOR_ORDER_FACTOR.get(it["author_order"], AUTHOR_ORDER_DEFAULT)
        total += _d(base) * _d(factor)
    cap_d = _d(cap)
    if total > cap_d:
        total = cap_d
    return round2(total)


def calc_total(gpa_score, comp_score, paper_score, rule):
    """加权求和。权重以百分数存储（85 表示 85%），所以除以 100。"""
    total = (
        _d(gpa_score) * _d(rule["gpa_weight"]) / 100
        + _d(comp_score) * _d(rule["comp_weight"]) / 100
        + _d(paper_score) * _d(rule["paper_weight"]) / 100
    )
    return round2(total)


# ---------------------------------------------------------------
# 排名构建
# ---------------------------------------------------------------

def _assign_rank(rows, key_score, out_key):
    """给已排好序的列表赋名次，总分相同则并列，后续名次顺延（1、1、3）。

    注意 out_key 必须区分学院内排名和专业内排名：
    同一个学生 dict 会被两轮排名各写一次，用同一个字段会互相覆盖。
    """
    prev_score = None
    prev_rank = 0
    for i, row in enumerate(rows, start=1):
        score = row[key_score]
        if prev_score is not None and score == prev_score:
            row[out_key] = prev_rank
        else:
            row[out_key] = i
            prev_rank = i
            prev_score = score


def build_ranking(db, year):
    """算出该年度的完整榜单。

    返回 dict：
        rows       —— 按学院内名次排好的学生列表（含各分项）
        stats      —— 覆盖率等口径统计
        rule       —— 本次计算所用的规则
    """
    rule = load_rule(db, year)

    students = db.execute(
        """
        SELECT s.id, s.student_no, s.name, s.gpa, s.gpa_scale,
               s.major_id, s.class_id,
               m.name AS major_name, c.name AS class_name,
               p.status AS part_status
        FROM student s
        JOIN major m ON m.id = s.major_id
        LEFT JOIN class_group c ON c.id = s.class_id
        LEFT JOIN participation p ON p.student_id = s.id AND p.year = ?
        WHERE s.enrollment_status = 'ACTIVE'
        ORDER BY s.student_no
        """,
        (year,),
    ).fetchall()

    comp_rows = db.execute(
        "SELECT student_id, level, award, team_rank FROM competition "
        "WHERE year = ? AND status = 'CONFIRMED'",
        (year,),
    ).fetchall()
    paper_rows = db.execute(
        "SELECT student_id, index_type, author_order FROM paper "
        "WHERE year = ? AND status = 'CONFIRMED'",
        (year,),
    ).fetchall()

    comp_by_student = {}
    for r in comp_rows:
        comp_by_student.setdefault(r["student_id"], []).append(dict(r))
    paper_by_student = {}
    for r in paper_rows:
        paper_by_student.setdefault(r["student_id"], []).append(dict(r))

    rows = []
    confirmed = 0
    for s in students:
        is_confirmed = s["part_status"] == "CONFIRMED"
        if is_confirmed:
            confirmed += 1
            gpa_s = calc_gpa_score(s["gpa"], s["gpa_scale"])
            comp_s = calc_competition_score(
                comp_by_student.get(s["id"], []), rule["comp_coef"], rule["comp_cap"]
            )
            paper_s = calc_paper_score(
                paper_by_student.get(s["id"], []), rule["paper_coef"], rule["paper_cap"]
            )
            total = calc_total(gpa_s, comp_s, paper_s, rule)
        else:
            gpa_s = comp_s = paper_s = total = 0.0

        rows.append({
            "student_id": s["id"],
            "student_no": s["student_no"],
            "name": s["name"],
            "masked_name": mask_name(s["name"]),
            "major_id": s["major_id"],
            "major_name": s["major_name"],
            "class_name": s["class_name"],
            "gpa": s["gpa"],
            "gpa_score": gpa_s,
            "comp_score": comp_s,
            "paper_score": paper_s,
            "total": total,
            "confirmed": is_confirmed,
        })

    # 只让已确认的学生进入排名，其余排在后面但不参与名次
    ranked = [r for r in rows if r["confirmed"]]
    ranked.sort(key=lambda r: (-r["total"], -r["gpa_score"], -r["comp_score"],
                               -r["paper_score"], r["student_no"]))
    _assign_rank(ranked, "total", "rank_college")

    # 专业内排名（会影响 rank_major，不影响 rank_college）
    by_major = {}
    for r in ranked:
        by_major.setdefault(r["major_id"], []).append(r)
    for group in by_major.values():
        _assign_rank(group, "total", "rank_major")

    total_students = len(students)
    stats = {
        "total_students": total_students,
        "confirmed": confirmed,
        "coverage": round2(_d(confirmed) / _d(total_students) * 100) if total_students else 0.0,
        "ranked": len(ranked),
    }
    return {"rows": ranked, "stats": stats, "rule": rule, "year": year}


def find_my_position(ranking, student_id):
    """在学生自己的视角里找出他的名次、专业内名次、与保研线的差距。"""
    for r in ranking["rows"]:
        if r["student_id"] == student_id:
            return r
    return None


def get_quota(db):
    """保研名额（V1.0 存在系统参数里，V1.1 再做成按专业分配）。"""
    row = db.execute("SELECT value FROM sys_config WHERE key = 'quota_current'").fetchone()
    return int(row["value"]) if row else 0


def cutoff_score(ranking, quota):
    """保研线 = 第 quota 名的综合成绩；人数不足时取最后一名。"""
    if quota <= 0 or not ranking["rows"]:
        return None
    if quota >= len(ranking["rows"]):
        return ranking["rows"][-1]["total"]
    return ranking["rows"][quota - 1]["total"]
