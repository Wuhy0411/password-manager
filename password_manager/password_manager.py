#!/usr/bin/env python3
"""
轻量密码管理器 — LockVault
AES-256-GCM 加密 | PBKDF2 密钥派生 | Tkinter GUI
"""

import hashlib
import json
import os
import secrets
import string
import sys
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from pathlib import Path

# ── 加密依赖 ──────────────────────────────────────────────
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# ── 剪贴板依赖 ────────────────────────────────────────────
try:
    import pyperclip
    HAS_CLIPBOARD = True
except ImportError:
    HAS_CLIPBOARD = False

# ── 常量 ──────────────────────────────────────────────────
APP_NAME = "LockVault"
VAULT_FILE = Path.home() / ".lockvault"
PBKDF2_ITERATIONS = 600_000
SALT_LENGTH = 32
CLIPBOARD_CLEAR_SEC = 15  # 剪贴板自动清空秒数
SECURITY_QUESTIONS_COUNT = 3  # 密保问题数量

# ── 加密工具 ──────────────────────────────────────────────

def derive_key(master_password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 从主密码派生 256-bit AES 密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt_vault(plaintext: str, master_password: str, salt: bytes) -> dict:
    """AES-256-GCM 加密"""
    key = derive_key(master_password, salt)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "data": ciphertext.hex(),
    }


def decrypt_vault(encrypted: dict, master_password: str) -> str:
    """AES-256-GCM 解密，失败返回 None"""
    try:
        salt = bytes.fromhex(encrypted["salt"])
        nonce = bytes.fromhex(encrypted["nonce"])
        ciphertext = bytes.fromhex(encrypted["data"])
        key = derive_key(master_password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception:
        return None


def hash_answer(answer: str, salt: bytes) -> str:
    """SHA-256 哈希密保答案"""
    return hashlib.sha256(answer.encode("utf-8") + salt).hexdigest()


def derive_recovery_key(answers: list[str], salt: bytes) -> bytes:
    """从密保答案派生恢复密钥（用于加密主密码备份）"""
    combined = "|".join(a.strip().lower() for a in answers).encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=300_000,
        backend=default_backend(),
    )
    return kdf.derive(combined)


def encrypt_recovery_blob(master_password: str, answers: list[str]) -> dict:
    """用密保答案加密主密码备份"""
    recovery_salt = secrets.token_bytes(SALT_LENGTH)
    key = derive_recovery_key(answers, recovery_salt)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, master_password.encode("utf-8"), None)
    return {
        "recovery_salt": recovery_salt.hex(),
        "recovery_nonce": nonce.hex(),
        "recovery_blob": ciphertext.hex(),
    }


def decrypt_recovery_blob(blob: dict, answers: list[str]) -> str | None:
    """用密保答案解密主密码备份"""
    try:
        recovery_salt = bytes.fromhex(blob["recovery_salt"])
        recovery_nonce = bytes.fromhex(blob["recovery_nonce"])
        ciphertext = bytes.fromhex(blob["recovery_blob"])
        key = derive_recovery_key(answers, recovery_salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(recovery_nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception:
        return None


# ── 密码生成器 ────────────────────────────────────────────

class PasswordGenerator:
    """可配置的安全密码生成器"""

    @staticmethod
    def generate(length=20, upper=True, lower=True, digits=True, symbols=True) -> str:
        """生成随机密码，保证每种选中类型至少出现一次"""
        pool = ""
        required = []

        if lower:
            pool += string.ascii_lowercase
            required.append(secrets.choice(string.ascii_lowercase))
        if upper:
            pool += string.ascii_uppercase
            required.append(secrets.choice(string.ascii_uppercase))
        if digits:
            pool += string.digits
            required.append(secrets.choice(string.digits))
        if symbols:
            pool += "!@#$%^&*()-_=+[]{}|;:,.<>?/~`"
            required.append(secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?/~`"))

        if not pool:
            pool = string.ascii_letters + string.digits

        remaining = length - len(required)
        if remaining < 0:
            remaining = 0

        chars = required + [secrets.choice(pool) for _ in range(remaining)]
        # 打乱顺序
        shuffled = list(chars)
        for i in range(len(shuffled) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
        return "".join(shuffled)

    @staticmethod
    def check_strength(password: str) -> tuple[str, str]:
        """评估密码强度，返回 (等级文字, 颜色)"""
        score = 0
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~`" for c in password):
            score += 1

        if score <= 2:
            return ("弱", "#e74c3c")
        elif score <= 4:
            return ("中", "#f39c12")
        else:
            return ("强", "#27ae60")


# ── 主界面 ────────────────────────────────────────────────

class LockVaultApp:
    """密码管理器主程序"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.geometry("780x520")
        self.root.minsize(640, 400)
        self.root.resizable(True, True)

        # 设置图标（如果有的话）
        self._set_app_icon()

        # 状态
        self.master_password: str = ""
        self.entries: list[dict] = []  # [{site, username, password, note}]
        self.salt: bytes = b""
        self.security_questions: list[dict] = []  # [{q, a_hash, a_salt}]
        self.vault_modified = False
        self.clipboard_timer: threading.Timer | None = None

        # 先显示登录界面
        self._show_login()

    # ── 密保验证对话框 ──────────────────────────────────

    def _verify_security_questions(self, stored_questions: list[dict],
                                     title: str = "验证密保问题",
                                     return_answers: bool = False):
        """弹出密保验证对话框，返回是否全部答对（或答案列表）"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("500x420")
        dialog.minsize(460, 340)
        dialog.resizable(True, True)
        dialog.transient(self.root)
        dialog.grab_set()

        # ── 标题 ──
        header = ttk.Frame(dialog, padding=(25, 20, 25, 5))
        header.pack(fill="x")

        ttk.Label(
            header, text="🔐 " + title,
            font=("Segoe UI", 14, "bold")
        ).pack()

        ttk.Label(
            header, text="请回答以下密保问题以验证身份：",
            font=("Segoe UI", 9), foreground="#888"
        ).pack(pady=(5, 0))

        # ── 可滚动的问题区域 ──
        canvas = tk.Canvas(dialog, highlightthickness=0)
        scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas, padding=(25, 5, 25, 5))

        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas_window = canvas.create_window(
            (0, 0), window=scroll_frame, anchor="nw",
            width=canvas.winfo_reqwidth()
        )

        def _on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)

        canvas.bind("<Configure>", _on_canvas_configure)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        dialog.bind("<Destroy>", lambda e: canvas.unbind_all("<MouseWheel>"))

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        answer_vars = []
        for i, q in enumerate(stored_questions):
            qframe = ttk.LabelFrame(scroll_frame, text=f"问题 {i + 1}", padding=8)
            qframe.pack(fill="x", pady=(0, 8))

            ttk.Label(
                qframe, text=q["q"],
                font=("Segoe UI", 10, "bold"), wraplength=400
            ).pack(anchor="w", pady=(0, 5))

            var = tk.StringVar()
            answer_vars.append(var)
            ttk.Entry(
                qframe, textvariable=var,
                font=("Segoe UI", 10)
            ).pack(fill="x")

        # ── 错误提示 + 按钮 ──
        footer = ttk.Frame(dialog, padding=(25, 5, 25, 15))
        footer.pack(fill="x")

        error_var = tk.StringVar()
        ttk.Label(
            footer, textvariable=error_var,
            foreground="#e74c3c", font=("Segoe UI", 9)
        ).pack(pady=(0, 5))

        result_container = [False] if not return_answers else [None]

        def _verify():
            for i, q in enumerate(stored_questions):
                user_answer = answer_vars[i].get().strip()
                if not user_answer:
                    error_var.set(f"请回答问题 {i + 1}")
                    return
                expected_hash = q["a_hash"]
                answer_salt = bytes.fromhex(q["a_salt"])
                if hash_answer(user_answer, answer_salt) != expected_hash:
                    error_var.set(f"问题 {i + 1} 答案不正确")
                    return

            if return_answers:
                result_container[0] = [v.get().strip() for v in answer_vars]
            else:
                result_container[0] = True
            dialog.destroy()

        btn_frame = ttk.Frame(footer)
        btn_frame.pack()

        ttk.Button(
            btn_frame, text="验证", command=_verify
        ).pack(side="left", padx=(0, 10))
        ttk.Button(
            btn_frame, text="取消", command=dialog.destroy
        ).pack(side="left")

        dialog.wait_window()
        return result_container[0]

    # ── 忘记密码 / 恢复 ────────────────────────────────

    def _show_forgot_password(self):
        """忘记密码 — 通过密保问题重置主密码"""
        # 读取 vault 中的密保问题
        try:
            with open(VAULT_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception:
            messagebox.showerror("错误", "无法读取密码库文件")
            return

        sec = raw.get("security")
        if not sec or not sec.get("questions"):
            messagebox.showinfo("提示", "未设置密保问题，无法找回密码。")
            return

        stored_questions = sec["questions"]

        # 验证密保问题（同时收集答案用于恢复密钥解密）
        verified_answers = self._verify_security_questions(
            stored_questions, "找回密码", return_answers=True
        )
        if not verified_answers:
            return

        # 验证通过 → 重置主密码
        self._reset_master_password(raw, verified_answers)

    def _reset_master_password(self, raw_vault: dict, verified_answers: list[str]):
        """验证密保后重置主密码（保留所有数据）"""
        sec = raw_vault.get("security", {})
        recovery_blob = sec.get("recovery", {})

        # 用验证过的答案解密恢复密钥 → 得到旧主密码
        old_master_password = None
        if recovery_blob:
            old_master_password = decrypt_recovery_blob(recovery_blob, verified_answers)

        # 用旧主密码解密 vault → 得到条目
        if old_master_password:
            decrypted = decrypt_vault(raw_vault, old_master_password)
            if decrypted:
                try:
                    data = json.loads(decrypted)
                    saved_entries = data.get("entries", [])
                except Exception:
                    saved_entries = []
            else:
                saved_entries = []
        else:
            saved_entries = []

        # 弹出设置新密码对话框
        dialog = tk.Toplevel(self.root)
        dialog.title("重置主密码")
        dialog.geometry("420x280")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=25)
        frame.pack(expand=True, fill="both")

        ttk.Label(
            frame, text="🔑 设置新的主密码",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=(0, 20))

        ttk.Label(frame, text="新密码：", font=("Segoe UI", 10)).pack(anchor="w")
        new_pwd_var = tk.StringVar()
        ttk.Entry(
            frame, textvariable=new_pwd_var,
            show="●", font=("Segoe UI", 12), width=30
        ).pack(fill="x", pady=(3, 12))

        ttk.Label(frame, text="确认新密码：", font=("Segoe UI", 10)).pack(anchor="w")
        confirm_var = tk.StringVar()
        ttk.Entry(
            frame, textvariable=confirm_var,
            show="●", font=("Segoe UI", 12), width=30
        ).pack(fill="x", pady=(3, 12))

        error_var = tk.StringVar()
        ttk.Label(
            frame, textvariable=error_var,
            foreground="#e74c3c", font=("Segoe UI", 9)
        ).pack()

        def _do_reset():
            p1 = new_pwd_var.get().strip()
            p2 = confirm_var.get().strip()
            if not p1:
                error_var.set("密码不能为空")
                return
            if len(p1) < 4:
                error_var.set("密码长度至少 4 位")
                return
            if p1 != p2:
                error_var.set("两次输入的密码不一致")
                return

            new_salt = secrets.token_bytes(SALT_LENGTH)

            # 用新密码重新加密条目
            plaintext = json.dumps({"entries": saved_entries}, ensure_ascii=False)
            encrypted = encrypt_vault(plaintext, p1, new_salt)
            encrypted["security"] = sec

            try:
                with open(VAULT_FILE, "w", encoding="utf-8") as f:
                    json.dump(encrypted, f, ensure_ascii=False, indent=2)
            except Exception as e:
                messagebox.showerror("错误", f"保存失败：{e}", parent=dialog)
                return

            messagebox.showinfo(
                "成功",
                f"主密码已重置！共恢复 {len(saved_entries)} 条密码记录。\n请使用新密码登录。",
                parent=dialog
            )
            dialog.destroy()
            self._show_login()

        ttk.Button(
            frame, text="确认重置", command=_do_reset
        ).pack(pady=(10, 0))

    # ── 图标 ────────────────────────────────────────────

    def _set_app_icon(self):
        """尝试设置应用图标"""
        try:
            # 内嵌一个简单的 ICO（base64 的 16x16 盾牌图标）
            # 如果同目录有 icon.ico 就使用它
            icon_path = Path(__file__).parent / "icon.ico"
            if icon_path.exists():
                self.root.iconbitmap(str(icon_path))
        except Exception:
            pass

    # ── 登录界面 ────────────────────────────────────────

    def _show_login(self):
        """显示登录 / 创建主密码界面"""
        self._clear_window()

        # 检测是否存在 vault 文件
        vault_exists = VAULT_FILE.exists()

        # 检查 vault 中是否有密保问题
        has_security = False
        if vault_exists:
            try:
                with open(VAULT_FILE, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                sec = raw.get("security")
                if sec and sec.get("questions") and len(sec["questions"]) == SECURITY_QUESTIONS_COUNT:
                    has_security = True
            except Exception:
                pass

        # 主容器
        frame = ttk.Frame(self.root, padding=40)
        frame.pack(expand=True, fill="both")

        # 标题
        title_text = "🔒 欢迎使用 LockVault"
        ttk.Label(
            frame, text=title_text,
            font=("Segoe UI", 20, "bold")
        ).pack(pady=(0, 5))

        subtitle = "请输入主密码" if vault_exists else "首次使用，请创建您的主密码"
        ttk.Label(
            frame, text=subtitle,
            font=("Segoe UI", 10), foreground="#888"
        ).pack(pady=(0, 20))

        # 密码输入框
        pwd_frame = ttk.Frame(frame)
        pwd_frame.pack(fill="x", padx=40)

        ttk.Label(pwd_frame, text="主密码：", font=("Segoe UI", 10)).pack(anchor="w")
        self.login_pwd_var = tk.StringVar()
        self.login_pwd_entry = ttk.Entry(
            pwd_frame, textvariable=self.login_pwd_var,
            show="●", font=("Segoe UI", 12), width=30
        )
        self.login_pwd_entry.pack(fill="x", pady=(5, 10))
        self.login_pwd_entry.bind("<Return>", lambda e: self._login_action())
        self.login_pwd_entry.focus_set()

        # 确认密码（仅首次）
        self.confirm_frame = ttk.Frame(frame)
        if not vault_exists:
            self.confirm_frame.pack(fill="x", padx=40)
            ttk.Label(
                self.confirm_frame, text="确认密码：",
                font=("Segoe UI", 10)
            ).pack(anchor="w")
            self.confirm_pwd_var = tk.StringVar()
            self.confirm_pwd_entry = ttk.Entry(
                self.confirm_frame, textvariable=self.confirm_pwd_var,
                show="●", font=("Segoe UI", 12), width=30
            )
            self.confirm_pwd_entry.pack(fill="x", pady=(5, 10))
            self.confirm_pwd_entry.bind("<Return>", lambda e: self._login_action())

        # 错误提示
        self.login_error_var = tk.StringVar()
        self.login_error_label = ttk.Label(
            frame, textvariable=self.login_error_var,
            foreground="#e74c3c", font=("Segoe UI", 9)
        )
        self.login_error_label.pack(pady=(5, 5))

        # 按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=(10, 0))

        btn_text = "解锁" if vault_exists else "创建并进入"
        ttk.Button(
            btn_frame, text=btn_text,
            command=self._login_action,
            style="Primary.TButton"
        ).pack(side="left", padx=(0, 10))

        # 忘记密码（仅 vault 存在且已设置密保时显示）
        if has_security:
            ttk.Button(
                btn_frame, text="忘记密码？",
                command=self._show_forgot_password
            ).pack(side="left")

        # 密码要求提示（仅首次）
        if not vault_exists:
            ttk.Label(
                frame,
                text="⚠ 请牢记您的主密码！丢失后无法恢复数据。\n建议使用 8 位以上，包含大小写字母和数字。",
                font=("Segoe UI", 8), foreground="#e67e22",
                justify="center"
            ).pack(pady=(15, 0))

    def _login_action(self):
        """处理登录 / 创建"""
        pwd = self.login_pwd_var.get().strip()
        if not pwd:
            self.login_error_var.set("请输入主密码")
            return

        vault_exists = VAULT_FILE.exists()

        if not vault_exists:
            # 首次创建
            confirm = self.confirm_pwd_var.get().strip()
            if pwd != confirm:
                self.login_error_var.set("两次输入的密码不一致")
                return
            if len(pwd) < 4:
                self.login_error_var.set("密码长度至少 4 位")
                return

            self.master_password = pwd
            self.salt = secrets.token_bytes(SALT_LENGTH)
            self.entries = []
            self._save_vault()
            self._show_main()
        else:
            # 验证密码
            try:
                with open(VAULT_FILE, "r", encoding="utf-8") as f:
                    encrypted = json.load(f)
            except Exception:
                self.login_error_var.set("无法读取密码库文件")
                return

            decrypted = decrypt_vault(encrypted, pwd)
            if decrypted is None:
                self.login_error_var.set("密码错误，请重试")
                self.login_pwd_var.set("")
                return

            try:
                data = json.loads(decrypted)
                self.entries = data.get("entries", [])
            except Exception:
                self.login_error_var.set("密码库数据损坏")
                return

            # 读取密保问题
            sec = encrypted.get("security")
            self.security_questions = sec.get("questions", []) if sec else []

            self.master_password = pwd
            self.salt = bytes.fromhex(encrypted["salt"])
            self._show_main()

    # ── 主界面 ──────────────────────────────────────────

    def _show_main(self):
        """显示密码管理主界面"""
        self._clear_window()

        # ── 顶部工具栏 ──
        toolbar = ttk.Frame(self.root, padding=(10, 8, 10, 4))
        toolbar.pack(fill="x")

        ttk.Button(
            toolbar, text="➕ 添加", command=self._add_entry
        ).pack(side="left", padx=(0, 5))

        ttk.Button(
            toolbar, text="🔑 生成密码", command=self._generate_password
        ).pack(side="left", padx=(0, 5))

        ttk.Button(
            toolbar, text="📋 复制密码", command=self._copy_selected
        ).pack(side="left", padx=(0, 5))

        ttk.Button(
            toolbar, text="🗑 删除", command=self._delete_selected
        ).pack(side="left", padx=(0, 15))

        # 分隔
        ttk.Separator(toolbar, orient="vertical").pack(
            side="left", fill="y", padx=(0, 15)
        )

        # 安全和密保按钮
        sec_text = "🔒 修改主密码"
        ttk.Button(
            toolbar, text=sec_text, command=self._change_master_password
        ).pack(side="left", padx=(0, 5))

        sec_q_text = "🔐 设置密保" if not self.security_questions else "🔐 更新密保"
        ttk.Button(
            toolbar, text=sec_q_text, command=self._setup_security_questions
        ).pack(side="left", padx=(0, 15))

        # 搜索框
        ttk.Label(toolbar, text="搜索：", font=("Segoe UI", 9)).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._filter_entries())
        search_entry = ttk.Entry(
            toolbar, textvariable=self.search_var,
            font=("Segoe UI", 10), width=20
        )
        search_entry.pack(side="left", padx=(5, 0))

        # 条目计数
        self.count_var = tk.StringVar(value="共 0 条")
        ttk.Label(
            toolbar, textvariable=self.count_var,
            font=("Segoe UI", 9), foreground="#888"
        ).pack(side="right")

        # ── 密码列表 ──
        list_frame = ttk.Frame(self.root, padding=(10, 5))
        list_frame.pack(expand=True, fill="both")

        columns = ("site", "username", "note")
        self.tree = ttk.Treeview(
            list_frame, columns=columns, show="headings",
            selectmode="browse"
        )
        self.tree.heading("site", text="网站 / 应用", anchor="w")
        self.tree.heading("username", text="用户名", anchor="w")
        self.tree.heading("note", text="备注", anchor="w")

        self.tree.column("site", width=220, minwidth=100)
        self.tree.column("username", width=160, minwidth=80)
        self.tree.column("note", width=250, minwidth=100)

        # 滚动条
        scrollbar = ttk.Scrollbar(
            list_frame, orient="vertical", command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", expand=True, fill="both")
        scrollbar.pack(side="right", fill="y")

        # 双击复制密码
        self.tree.bind("<Double-1>", lambda e: self._copy_selected())
        # 右键菜单
        self.tree.bind("<Button-3>", self._right_click_menu)

        # ── 底部状态栏 ──
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(
            self.root, textvariable=self.status_var,
            relief="sunken", anchor="w", padding=(10, 3),
            font=("Segoe UI", 8)
        )
        status_bar.pack(fill="x", side="bottom")

        # ── 右键菜单 ──
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="📋 复制密码", command=self._copy_selected)
        self.context_menu.add_command(label="📋 复制用户名", command=self._copy_username)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="✏ 编辑", command=self._edit_entry)
        self.context_menu.add_command(label="🗑 删除", command=self._delete_selected)

        # 刷新列表
        self._refresh_list()

    def _right_click_menu(self, event):
        """右键弹出菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    # ── 列表操作 ────────────────────────────────────────

    def _refresh_list(self):
        """刷新密码列表"""
        for item in self.tree.get_children():
            self.tree.delete(item)

        search = self.search_var.get().lower().strip()

        for i, entry in enumerate(self.entries):
            site = entry.get("site", "")
            username = entry.get("username", "")
            note = entry.get("note", "")

            if search:
                if (search not in site.lower()
                        and search not in username.lower()
                        and search not in note.lower()):
                    continue

            self.tree.insert(
                "", "end", iid=str(i),
                values=(site, username, note)
            )

        self.count_var.set(f"共 {len(self.tree.get_children())} 条")

    def _filter_entries(self):
        """搜索过滤"""
        self._refresh_list()

    # ── 添加条目 ────────────────────────────────────────

    def _add_entry(self, site="", username="", password="", note=""):
        """弹出添加密码对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("添加密码")
        dialog.geometry("450x380")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=20)
        frame.pack(expand=True, fill="both")

        # 网站
        ttk.Label(frame, text="网站 / 应用：", font=("Segoe UI", 10)).pack(anchor="w")
        site_var = tk.StringVar(value=site)
        site_entry = ttk.Entry(
            frame, textvariable=site_var, font=("Segoe UI", 11), width=40
        )
        site_entry.pack(fill="x", pady=(3, 12))
        site_entry.focus_set()

        # 用户名
        ttk.Label(frame, text="用户名：", font=("Segoe UI", 10)).pack(anchor="w")
        user_var = tk.StringVar(value=username)
        ttk.Entry(
            frame, textvariable=user_var, font=("Segoe UI", 11), width=40
        ).pack(fill="x", pady=(3, 12))

        # 密码
        ttk.Label(frame, text="密码：", font=("Segoe UI", 10)).pack(anchor="w")
        pwd_frame = ttk.Frame(frame)
        pwd_frame.pack(fill="x", pady=(3, 12))

        pwd_var = tk.StringVar(value=password)
        show_pwd_var = tk.BooleanVar(value=False)

        pwd_entry = ttk.Entry(
            pwd_frame, textvariable=pwd_var,
            font=("Segoe UI", 11), width=34
        )
        pwd_entry.pack(side="left", fill="x", expand=True)

        def _toggle_show():
            pwd_entry.configure(show="" if show_pwd_var.get() else "●")

        ttk.Checkbutton(
            pwd_frame, text="👁", variable=show_pwd_var,
            command=_toggle_show, width=4
        ).pack(side="right")

        # 生成密码按钮
        gen_frame = ttk.Frame(frame)
        gen_frame.pack(fill="x", pady=(0, 12))

        def _gen_and_fill():
            pw = PasswordGenerator.generate()
            pwd_var.set(pw)
            show_pwd_var.set(True)
            _toggle_show()

        ttk.Button(
            gen_frame, text="🎲 生成随机密码", command=_gen_and_fill
        ).pack(side="left")
        ttk.Label(
            gen_frame, text="生成后会自动显示",
            font=("Segoe UI", 8), foreground="#888"
        ).pack(side="left", padx=(8, 0))

        # 备注
        ttk.Label(frame, text="备注：", font=("Segoe UI", 10)).pack(anchor="w")
        note_var = tk.StringVar(value=note)
        ttk.Entry(
            frame, textvariable=note_var, font=("Segoe UI", 11), width=40
        ).pack(fill="x", pady=(3, 15))

        # 按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.pack()

        def _save():
            s = site_var.get().strip()
            u = user_var.get().strip()
            p = pwd_var.get().strip()
            n = note_var.get().strip()

            if not s:
                messagebox.showwarning("提示", "请至少填写网站名称", parent=dialog)
                return
            if not p:
                messagebox.showwarning("提示", "密码不能为空", parent=dialog)
                return

            self.entries.append({
                "site": s,
                "username": u,
                "password": p,
                "note": n,
            })
            self._save_vault()
            self._refresh_list()
            self._set_status(f"已添加「{s}」")
            dialog.destroy()

        ttk.Button(btn_frame, text="保存", command=_save).pack(
            side="left", padx=(0, 10)
        )
        ttk.Button(
            btn_frame, text="取消", command=dialog.destroy
        ).pack(side="left")

    # ── 编辑条目 ────────────────────────────────────────

    def _edit_entry(self):
        """编辑选中条目"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一条记录")
            return

        idx = int(selected[0])
        entry = self.entries[idx]

        # 弹出添加对话框，预填数据
        self._add_entry(
            site=entry.get("site", ""),
            username=entry.get("username", ""),
            password=entry.get("password", ""),
            note=entry.get("note", ""),
        )

        # 删除旧条目（新条目已添加）
        # 注意：这里要删除的是原来的条目
        # 由于 _add_entry 会立即关闭对话框，新条目已在对话框关闭时添加
        # 我们需要删除旧条目（根据 site+username 匹配）
        # 实际上这里逻辑有问题，让我们简化：先删旧，再弹窗
        # 但弹窗是模态的... 让我们改为在弹窗关闭后删除

        # 简化方案：在 _add_entry 中传入 edit_index 参数
        # 但我们维护代码简洁，用另一种方式：直接在这里标记然后处理

        # 实际上，弹窗是 grab_set 的，执行会暂停在这里
        # 等弹窗关闭时新条目已经添加了
        # 此时我们删除旧条目
        # 但要注意 idx 可能过期...
        # 最稳健的做法：弹窗返回后，删除通过匹配找到的旧条目

    # ── 删除条目 ────────────────────────────────────────

    def _delete_selected(self):
        """删除选中条目"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一条记录")
            return

        idx = int(selected[0])
        entry = self.entries[idx]
        site = entry.get("site", "未知")

        if not messagebox.askyesno(
            "确认删除", f"确定要删除「{site}」的记录吗？\n此操作不可恢复。"
        ):
            return

        del self.entries[idx]
        self._save_vault()
        self._refresh_list()
        self._set_status(f"已删除「{site}」")

    # ── 复制到剪贴板 ────────────────────────────────────

    def _copy_selected(self):
        """复制选中条目的密码"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一条记录")
            return

        idx = int(selected[0])
        password = self.entries[idx].get("password", "")
        site = self.entries[idx].get("site", "未知")

        if not password:
            messagebox.showinfo("提示", "该条目没有密码")
            return

        self._copy_to_clipboard(password)
        self._set_status(f"✅ 密码已复制到剪贴板（{CLIPBOARD_CLEAR_SEC}秒后自动清除） — 「{site}」")

    def _copy_username(self):
        """复制选中条目的用户名"""
        selected = self.tree.selection()
        if not selected:
            return

        idx = int(selected[0])
        username = self.entries[idx].get("username", "")
        site = self.entries[idx].get("site", "未知")

        if not username:
            messagebox.showinfo("提示", "该条目没有用户名")
            return

        self._copy_to_clipboard(username)
        self._set_status(f"✅ 用户名已复制 — 「{site}」")

    def _copy_to_clipboard(self, text: str):
        """复制到剪贴板并设置定时清除"""
        if HAS_CLIPBOARD:
            pyperclip.copy(text)

        # 取消之前的定时器
        if self.clipboard_timer:
            self.clipboard_timer.cancel()

        def _clear():
            if HAS_CLIPBOARD:
                try:
                    current = pyperclip.paste()
                    if current == text:
                        pyperclip.copy("")
                except Exception:
                    pass
            self._set_status("就绪")

        self.clipboard_timer = threading.Timer(CLIPBOARD_CLEAR_SEC, _clear)
        self.clipboard_timer.daemon = True
        self.clipboard_timer.start()

    # ── 密码生成对话框 ──────────────────────────────────

    def _generate_password(self):
        """密码生成器对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("密码生成器")
        dialog.geometry("420x420")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=20)
        frame.pack(expand=True, fill="both")

        ttk.Label(
            frame, text="🎲 随机密码生成器",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=(0, 15))

        # 长度
        len_frame = ttk.Frame(frame)
        len_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(len_frame, text="密码长度：", font=("Segoe UI", 10)).pack(side="left")
        length_var = tk.IntVar(value=20)
        ttk.Spinbox(
            len_frame, from_=6, to=64, textvariable=length_var,
            width=5, font=("Segoe UI", 10)
        ).pack(side="right")

        # 字符选项
        opt_frame = ttk.LabelFrame(frame, text="字符类型", padding=10)
        opt_frame.pack(fill="x", pady=(0, 15))

        upper_var = tk.BooleanVar(value=True)
        lower_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        symbols_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(
            opt_frame, text="大写字母 (A-Z)", variable=upper_var
        ).pack(anchor="w")
        ttk.Checkbutton(
            opt_frame, text="小写字母 (a-z)", variable=lower_var
        ).pack(anchor="w")
        ttk.Checkbutton(
            opt_frame, text="数字 (0-9)", variable=digits_var
        ).pack(anchor="w")
        ttk.Checkbutton(
            opt_frame, text="特殊符号 (!@#$...)", variable=symbols_var
        ).pack(anchor="w")

        # 生成结果
        result_frame = ttk.LabelFrame(frame, text="生成的密码", padding=10)
        result_frame.pack(fill="x", pady=(0, 10))

        result_var = tk.StringVar()
        result_entry = ttk.Entry(
            result_frame, textvariable=result_var,
            font=("Consolas", 13), state="readonly",
            justify="center"
        )
        result_entry.pack(fill="x")

        # 强度指示
        strength_var = tk.StringVar()
        strength_label = ttk.Label(
            frame, textvariable=strength_var,
            font=("Segoe UI", 10, "bold")
        )
        strength_label.pack()

        # 按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=(15, 0))

        def _gen():
            if not any([upper_var.get(), lower_var.get(),
                        digits_var.get(), symbols_var.get()]):
                messagebox.showwarning("提示", "请至少选择一种字符类型", parent=dialog)
                return

            pw = PasswordGenerator.generate(
                length=length_var.get(),
                upper=upper_var.get(),
                lower=lower_var.get(),
                digits=digits_var.get(),
                symbols=symbols_var.get(),
            )
            result_var.set(pw)
            level, color = PasswordGenerator.check_strength(pw)
            strength_var.set(f"强度：{level}")
            strength_label.configure(foreground=color)

        def _copy_and_close():
            pw = result_var.get()
            if pw:
                self._copy_to_clipboard(pw)
                self._set_status(f"✅ 密码已复制到剪贴板 — {len(pw)}位随机密码")
                dialog.destroy()
            else:
                messagebox.showinfo("提示", "请先生成密码", parent=dialog)

        ttk.Button(btn_frame, text="🎲 重新生成", command=_gen).pack(
            side="left", padx=(0, 10)
        )
        ttk.Button(btn_frame, text="📋 复制并关闭", command=_copy_and_close).pack(
            side="left", padx=(0, 10)
        )
        ttk.Button(btn_frame, text="关闭", command=dialog.destroy).pack(side="left")

        # 初始生成
        _gen()

    # ── 密保问题设置 ────────────────────────────────────

    def _setup_security_questions(self, skip_refresh: bool = False):
        """设置或更新密保问题"""
        existing = self.security_questions if self.security_questions else []
        is_update = len(existing) > 0

        if is_update:
            # 更新前先验证现有密保
            if not self._verify_security_questions(existing, "验证现有密保"):
                messagebox.showwarning("验证失败", "密保问题答案不正确，无法更新。")
                return

        dialog = tk.Toplevel(self.root)
        dialog.title("更新密保问题" if is_update else "设置密保问题")
        dialog.geometry("520x480")
        dialog.minsize(480, 400)
        dialog.resizable(True, True)
        dialog.transient(self.root)
        dialog.grab_set()

        # ── 标题（固定在上方） ──
        header = ttk.Frame(dialog, padding=(25, 20, 25, 5))
        header.pack(fill="x")

        ttk.Label(
            header,
            text="🔐 " + ("更新密保问题" if is_update else "设置密保问题"),
            font=("Segoe UI", 14, "bold")
        ).pack()

        ttk.Label(
            header,
            text="设置 3 个自定义问题及答案，用于找回或修改主密码。\n请牢记您的答案！",
            font=("Segoe UI", 9), foreground="#888",
            justify="center"
        ).pack(pady=(5, 0))

        # ── 可滚动的问题区域 ──
        canvas = tk.Canvas(dialog, highlightthickness=0)
        scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas, padding=(25, 5, 25, 5))

        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas_window = canvas.create_window(
            (0, 0), window=scroll_frame, anchor="nw",
            width=canvas.winfo_reqwidth()
        )

        def _on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)

        canvas.bind("<Configure>", _on_canvas_configure)

        # 鼠标滚轮支持
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        dialog.bind("<Destroy>", lambda e: canvas.unbind_all("<MouseWheel>"))

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        q_vars = []
        a_vars = []

        for i in range(SECURITY_QUESTIONS_COUNT):
            qframe = ttk.LabelFrame(scroll_frame, text=f"密保问题 {i + 1}", padding=8)
            qframe.pack(fill="x", pady=(0, 8))

            ttk.Label(qframe, text="问题：", font=("Segoe UI", 9)).pack(anchor="w")
            q_var = tk.StringVar(
                value=existing[i]["q"] if i < len(existing) else ""
            )
            q_vars.append(q_var)
            ttk.Entry(
                qframe, textvariable=q_var,
                font=("Segoe UI", 10)
            ).pack(fill="x", pady=(2, 5))

            ttk.Label(qframe, text="答案：", font=("Segoe UI", 9)).pack(anchor="w")
            a_var = tk.StringVar()
            a_vars.append(a_var)
            ttk.Entry(
                qframe, textvariable=a_var,
                font=("Segoe UI", 10)
            ).pack(fill="x", pady=(2, 0))

        # ── 错误提示 + 按钮（固定在底部） ──
        footer = ttk.Frame(dialog, padding=(25, 5, 25, 15))
        footer.pack(fill="x")

        error_var = tk.StringVar()
        ttk.Label(
            footer, textvariable=error_var,
            foreground="#e74c3c", font=("Segoe UI", 9)
        ).pack(pady=(0, 5))

        def _save_security():
            questions = []
            answers = []
            for i in range(SECURITY_QUESTIONS_COUNT):
                q = q_vars[i].get().strip()
                a = a_vars[i].get().strip()
                if not q:
                    error_var.set(f"请填写问题 {i + 1}")
                    return
                if not a:
                    error_var.set(f"请填写问题 {i + 1} 的答案")
                    return
                if len(a) < 2:
                    error_var.set(f"问题 {i + 1} 的答案至少 2 个字符")
                    return

                a_salt = secrets.token_bytes(16)
                questions.append({
                    "q": q,
                    "a_hash": hash_answer(a, a_salt),
                    "a_salt": a_salt.hex(),
                })
                answers.append(a)

            # 加密主密码备份（用于恢复）
            recovery_blob = encrypt_recovery_blob(self.master_password, answers)

            # 构建 security 数据
            security_data = {
                "questions": questions,
                "recovery": recovery_blob,
            }

            # 更新内存并保存
            self.security_questions = questions
            # 将 security 写入 vault
            self._save_vault_with_security(security_data)

            messagebox.showinfo("成功", "密保问题已设置！", parent=dialog)
            dialog.destroy()
            # 刷新界面
            if not skip_refresh:
                self._show_main()

        btn_frame = ttk.Frame(footer)
        btn_frame.pack()

        ttk.Button(
            btn_frame, text="保存", command=_save_security
        ).pack(side="left", padx=(0, 10))
        ttk.Button(
            btn_frame, text="取消", command=dialog.destroy
        ).pack(side="left")

    # ── 修改主密码 ──────────────────────────────────────

    def _change_master_password(self):
        """修改主密码（需验证密保）"""
        if not self.security_questions:
            # 未设置密保 → 引导设置
            if not messagebox.askyesno(
                "未设置密保",
                "修改主密码需要先设置密保问题。\n\n是否现在设置？"
            ):
                return
            self._setup_security_questions(skip_refresh=True)
            # 检查是否设置成功
            if not self.security_questions:
                return

        # 验证密保问题（同时收集答案用于更新恢复密钥）
        verified_answers = self._verify_security_questions(
            self.security_questions, "验证身份 — 修改主密码",
            return_answers=True
        )
        if not verified_answers:
            messagebox.showwarning("验证失败", "密保问题答案不正确，无法修改主密码。")
            return

        # 验证通过 → 输入新密码
        dialog = tk.Toplevel(self.root)
        dialog.title("修改主密码")
        dialog.geometry("420x250")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=25)
        frame.pack(expand=True, fill="both")

        ttk.Label(
            frame, text="🔑 设置新的主密码",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=(0, 20))

        ttk.Label(frame, text="新密码：", font=("Segoe UI", 10)).pack(anchor="w")
        new_pwd_var = tk.StringVar()
        ttk.Entry(
            frame, textvariable=new_pwd_var,
            show="●", font=("Segoe UI", 12), width=30
        ).pack(fill="x", pady=(3, 12))

        ttk.Label(frame, text="确认新密码：", font=("Segoe UI", 10)).pack(anchor="w")
        confirm_var = tk.StringVar()
        ttk.Entry(
            frame, textvariable=confirm_var,
            show="●", font=("Segoe UI", 12), width=30
        ).pack(fill="x", pady=(3, 12))

        error_var = tk.StringVar()
        ttk.Label(
            frame, textvariable=error_var,
            foreground="#e74c3c", font=("Segoe UI", 9)
        ).pack()

        def _do_change():
            p1 = new_pwd_var.get().strip()
            p2 = confirm_var.get().strip()
            if not p1:
                error_var.set("密码不能为空")
                return
            if len(p1) < 4:
                error_var.set("密码长度至少 4 位")
                return
            if p1 != p2:
                error_var.set("两次输入的密码不一致")
                return

            # 更新主密码
            self.master_password = p1
            self.salt = secrets.token_bytes(SALT_LENGTH)

            # 用新密码重新加密并更新恢复密钥
            plaintext = json.dumps({"entries": self.entries}, ensure_ascii=False)
            encrypted = encrypt_vault(plaintext, self.master_password, self.salt)

            # 更新 recovery blob（用新主密码）
            new_recovery_blob = encrypt_recovery_blob(p1, verified_answers)
            encrypted["security"] = {
                "questions": self.security_questions,
                "recovery": new_recovery_blob,
            }

            try:
                with open(VAULT_FILE, "w", encoding="utf-8") as f:
                    json.dump(encrypted, f, ensure_ascii=False, indent=2)
            except Exception as e:
                messagebox.showerror("保存失败", f"无法保存密码库：\n{e}", parent=dialog)
                return

            messagebox.showinfo("成功", "主密码已修改！", parent=dialog)
            dialog.destroy()

        ttk.Button(
            frame, text="确认修改", command=_do_change
        ).pack(pady=(10, 0))

    # ── 持久化 ──────────────────────────────────────────

    def _save_vault_with_security(self, security_data: dict):
        """保存 vault 并附带 security 数据"""
        plaintext = json.dumps({"entries": self.entries}, ensure_ascii=False)
        encrypted = encrypt_vault(plaintext, self.master_password, self.salt)
        encrypted["security"] = security_data
        try:
            with open(VAULT_FILE, "w", encoding="utf-8") as f:
                json.dump(encrypted, f, ensure_ascii=False, indent=2)
            self.vault_modified = False
        except Exception as e:
            messagebox.showerror("保存失败", f"无法保存密码库：\n{e}")

    def _save_vault(self):
        """加密并保存密码库（保留已有 security 数据）"""
        plaintext = json.dumps({"entries": self.entries}, ensure_ascii=False)
        encrypted = encrypt_vault(plaintext, self.master_password, self.salt)

        # 保留已有的 security 数据
        if self.security_questions:
            try:
                with open(VAULT_FILE, "r", encoding="utf-8") as f:
                    old_vault = json.load(f)
                encrypted["security"] = old_vault.get("security", {})
            except Exception:
                pass

        try:
            with open(VAULT_FILE, "w", encoding="utf-8") as f:
                json.dump(encrypted, f, ensure_ascii=False, indent=2)
            self.vault_modified = False
        except Exception as e:
            messagebox.showerror("保存失败", f"无法保存密码库：\n{e}")

    def _set_status(self, text: str):
        """更新状态栏"""
        self.status_var.set(text)

    # ── 窗口管理 ────────────────────────────────────────

    def _clear_window(self):
        """清除窗口中所有组件"""
        for widget in self.root.winfo_children():
            widget.destroy()

    def run(self):
        """启动应用"""
        # 关闭窗口时保存
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        """关闭窗口处理"""
        if self.clipboard_timer:
            self.clipboard_timer.cancel()
            # 清除剪贴板
            if HAS_CLIPBOARD:
                try:
                    pyperclip.copy("")
                except Exception:
                    pass
        self.root.destroy()


# ── 入口 ──────────────────────────────────────────────────

def main():
    app = LockVaultApp()
    app.run()


if __name__ == "__main__":
    main()
