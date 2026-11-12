# 数据库设计说明

对应 `schema.sql`，共 11 张表。SQLite 语法，迁 MySQL 只需把 `AUTOINCREMENT` 换成 `AUTO_INCREMENT`、`TEXT` 换成 `VARCHAR`。

## 分层

```
组织层    college → major → class_group
账号层    sys_user ──1:1── student
业务层    student ──1:N── competition / paper
          student ──1:1── participation（按年度）
规则层    score_rule（按年度 + 版本，只增不改）
支撑层    audit_log / sys_config
```

## 表清单

| 表 | 作用 | 关键字段 |
|---|---|---|
| `college` | 学院 | 目前只有「管理学院」一条 |
| `major` | 专业 | 工商管理、会计学、信管、市场营销、物流管理 |
| `class_group` | 班级 | 归属专业，绑定辅导员 |
| `sys_user` | 统一账号 | 学号/工号、PBKDF2 哈希、四种角色；`must_change_pwd` 首登强制改密、`failed_attempts` / `locked_until` 登录失败锁定（V1.0.1 起被 `app.py` 读取） |
| `student` | 学生档案 | 绩点存这里，`enrollment_status` 非 ACTIVE 不参与排名 |
| `competition` | 竞赛明细 | 级别 × 获奖等级 × 本人排名 |
| `paper` | 论文明细 | 分区 × 作者排序 |
| `participation` | 参与状态 | DRAFT / CONFIRMED / WITHDRAWN，唯一约束 `(student_id, year)` |
| `score_rule` | 评分规则 | 三项权重、系数 JSON、版本号、ACTIVE/ARCHIVED |
| `audit_log` | 审计日志 | 只追加，PRD 第 10 章硬要求 |
| `sys_config` | 系统参数 | 名额、冻结时间、当前年度 |

## 三个设计决定

**1. 权重不落代码，落表。**
`score_rule` 每改一次权重就插入新行、把旧行置为 ARCHIVED。这样「按届生效、历史可查、可对比」是天然支持的，不需要额外代码。`comp_coef` / `paper_coef` 用 JSON 存，因为系数是二维表（级别 × 奖项），拆成关系表反而增加查询复杂度，而它永远整体读写。

**2. 参与状态独立成表，不塞进 student。**
因为它是「学生 × 年度」的维度。如果做成 `student.confirmed` 字段，明年推免就得改表结构。独立表后，跨届数据天然隔离（PRD 8.1「学生数据按学生+周期隔离」）。

**3. 状态用 TEXT + CHECK，不用整数。**
`CHECK (status IN ('DRAFT','CONFIRMED'))` 在 SQLite 里等价于枚举约束，报错信息可读，查数据时一眼看懂。用 0/1/2 存状态，三个月后自己都不记得哪个数字是什么。

## 与 PRD 的对应

| PRD 条款 | 落点 |
|---|---|
| 4.1 组织与账号 | `college` / `major` / `class_group` / `sys_user` |
| 4.1 规则配置按届 | `score_rule.year` + `version` |
| 8.1 总分公式 | `score_rule` 三项权重 + 两个系数 JSON |
| 8.1 同分并列 | 无字段，纯计算逻辑（见 `scoring._assign_rank`） |
| 8.1 参与排名总人数 | 由 `student.enrollment_status` + `participation` 推出 |
| 10 留痕 | `audit_log` |
| 9.1 参数两级 | `sys_config`（V1.0 只有学校级，学院覆盖在 V1.1 加 `college_id`） |

## V1.1 扩展位

已经预留、加功能时不用重建表的地方：

- `competition.status` / `paper.status`：现在 `DRAFT|CONFIRMED`，加审核流时扩成 `PENDING|APPROVED|REJECTED|EXPIRED`
- `audit_log`：已含 `role` / `ip` / `detail`，够用
- `sys_config`：加 `college_id` 列即可支持学院级覆盖
- 附件：新建 `attachment(biz_type, biz_id, path, mime, size)`，用多态关联挂到任意业务对象，不用给每张表加文件字段

还没建但 V1.1 必须要的表：`review_log`（审核流水）、`ranking_snapshot`（冻结快照）、`notification`（站内通知）。
