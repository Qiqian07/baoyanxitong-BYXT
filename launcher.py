# -*- coding: utf-8 -*-
"""保研评估系统 · 本地启动器（纯标准库，Python 3.9+）。

为什么需要它：
Windows 上 `python` 这个名字经常指向 Microsoft Store 的占位程序，或者指向
自带的精简 Python（没有 pip）。直接 `python app.py` 就会报
`No module named 'flask'`，窗口一闪而过，看起来像"双击没反应"。

这个脚本负责把启动前该做的检查都做完：
1. 检查 Flask，缺了就装（清华镜像优先，失败再走官方源）
2. instance/baoyan.db 不存在就调用 seed.py 生成演示数据
3. 5000 端口被占：如果占着的就是本系统，直接打开浏览器；否则自动换 5001~5019
4. 自动打开浏览器，然后启动 Flask

用法：双击 run.bat（推荐），或命令行 `python launcher.py`。
"""

import importlib.util
import os
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
import webbrowser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

DB_PATH = os.path.join(BASE_DIR, "instance", "baoyan.db")

PREFERRED_PORT = 5000
PORT_TRIES = 20
MIRRORS = (
    ("https://pypi.tuna.tsinghua.edu.cn/simple", "清华镜像"),
    ("https://mirrors.aliyun.com/pypi/simple", "阿里云镜像"),
    (None, "官方源 pypi.org"),
)

LINE = "=" * 60


def setup_console():
    """Windows cmd 默认 GBK，输出中文/emoji 会炸；统一改成 UTF-8。"""
    if os.name == "nt":
        os.system("")  # 让控制台支持 ANSI 颜色
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def say(msg=""):
    print(msg, flush=True)


def banner():
    say(LINE)
    say("  保研评估系统  ·  武汉纺织大学管理学院")
    say(LINE)
    say(f"  Python : {sys.version.split()[0]}  ({sys.executable})")
    say("")


def has_flask():
    """真正 import 一次，避免"装了一半"的残骸被误判为可用。"""
    if importlib.util.find_spec("flask") is None:
        return False
    try:
        import flask  # noqa: F401
        return True
    except Exception:
        return False


def pip_available():
    try:
        return subprocess.call(
            [sys.executable, "-m", "pip", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ) == 0
    except Exception:
        return False


def ensure_flask():
    if has_flask():
        say("[1/3] Flask 已安装 ✓")
        return True

    say("[1/3] 缺少 Flask，准备自动安装 ...")
    if not pip_available():
        say("")
        say("  ✗ 当前这个 Python 没有可用的 pip，装不了依赖。")
        say("    常见原因：它是 Windows 商店占位程序、或精简版/嵌入式 Python。")
        say("")
        say("  解决办法（二选一）：")
        say("    A. 装官方 Python：https://www.python.org/downloads/windows/")
        say("       下载 Windows installer (64-bit)，安装第一页勾选"
            "「Add python.exe to PATH」")
        say("    B. 把本机可用的 python.exe 完整路径发给负责人，由他补进 run.bat")
        return False

    for index, url, label in MIRRORS:
        cmd = [sys.executable, "-m", "pip", "install",
               "--disable-pip-version-check", "Flask>=3.0"]
        if url:
            cmd += ["--index-url", url, "--trusted-host", url.split("/")[2]]
        say(f"      正在从{label}安装 Flask ...")
        if subprocess.call(cmd) == 0 and has_flask():
            say("[1/3] Flask 安装完成 ✓")
            return True

    say("")
    say("  ✗ Flask 自动安装失败，通常是网络问题。请手动执行：")
    say(f'    "{sys.executable}" -m pip install Flask -i '
        "https://pypi.tuna.tsinghua.edu.cn/simple")
    return False


def ensure_database():
    if os.path.exists(DB_PATH) and os.path.getsize(DB_PATH) > 0:
        say("[2/3] 数据库已就绪 ✓")
        return True

    say("[2/3] 首次运行，正在生成演示数据（146 名学生）...")
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    code = subprocess.call([sys.executable, os.path.join(BASE_DIR, "seed.py")])
    if code != 0 or not os.path.exists(DB_PATH):
        say("")
        say("  ✗ 演示数据生成失败，上面是 seed.py 的报错原文。")
        say("    可以手动重跑：python seed.py")
        return False
    say("[2/3] 演示数据生成完成 ✓")
    return True


def port_free(port):
    """不加 SO_REUSEADDR：Windows 上它会允许抢占已监听端口，判断会失真。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def app_already_running(port):
    """对比页面特征，确认占着端口的确实是本项目，而不是别的程序。"""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{port}/login", timeout=1.5) as resp:
            body = resp.read(8192).decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(8192).decode("utf-8", "ignore")
        except Exception:
            return False
    except Exception:
        return False
    return "保研" in body or "baoyan" in body.lower()


def pick_port():
    """返回 (port, already_running)。"""
    if port_free(PREFERRED_PORT):
        return PREFERRED_PORT, False
    if app_already_running(PREFERRED_PORT):
        return PREFERRED_PORT, True
    for port in range(PREFERRED_PORT + 1, PREFERRED_PORT + PORT_TRIES):
        if port_free(port):
            say(f"[3/3] 端口 {PREFERRED_PORT} 被其它程序占用，改用 {port}")
            return port, False
    return None, False


def open_browser_later(url, delay=1.6):
    def worker():
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Timer(delay, worker).start()


def run_server(port):
    url = f"http://127.0.0.1:{port}"
    say(f"[3/3] 服务已启动 → {url}")
    say("")
    say("  演示账号（密码统一 wt2026，首次登录须改密码）：")
    say("    学生      2023010101")
    say("    辅导员    T2001")
    say("    学院管理员 A1001")
    say("")
    say("  浏览器没自动弹出，就手动打开上面那个地址。")
    say("  关闭服务：回到这个黑窗口按 Ctrl+C，或直接关掉窗口。")
    say("")

    open_browser_later(url)

    from app import create_app

    application = create_app()
    application.run(host="127.0.0.1", port=port, debug=False,
                    use_reloader=False, threaded=True)


def main():
    setup_console()
    banner()

    if not ensure_flask():
        return 1
    if not ensure_database():
        return 1

    port, running = pick_port()
    if port is None:
        say(f"[3/3] 5000~{PREFERRED_PORT + PORT_TRIES} 端口全被占用，"
            "请先关掉占用端口的程序。")
        return 1
    if running:
        url = f"http://127.0.0.1:{port}"
        say(f"[3/3] 本系统已经在 {url} 运行，已为你打开浏览器。")
        say("")
        say("  想重新启动的话：先关掉之前那个黑窗口（或在里面按 Ctrl+C），再双击 run.bat。")
        webbrowser.open(url)
        return 2

    try:
        run_server(port)
    except KeyboardInterrupt:
        say("\n已停止服务。")
    except Exception as exc:
        say("")
        say(f"  ✗ 启动失败：{type(exc).__name__}: {exc}")
        say("    如果提示端口被占用（WinError 10048），说明上一次的窗口还没关闭。")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
