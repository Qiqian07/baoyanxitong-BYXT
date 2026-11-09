"""数据库连接与初始化。

用 Flask 的 g 对象按请求复用连接，避免每个函数都自己开关数据库。
"""

import os
import sqlite3

import click
from flask import current_app, g

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "baoyan.db")


def get_db():
    """取得当前请求的数据库连接（没有就新建一个）。"""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """按 schema.sql 重建所有表（会清空数据，只在初始化/重置时用）。"""
    db = get_db()
    with current_app.open_resource("schema.sql") as f:
        db.executescript(f.read().decode("utf-8"))
    db.commit()


@click.command("init-db")
def init_db_command():
    """命令行：flask init-db —— 建表。"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    init_db()
    click.echo("数据库表已创建：instance/baoyan.db")


def register(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
