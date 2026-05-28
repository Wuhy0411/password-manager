"""从 Edge 浏览器导出保存的密码 → Markdown 表格（支持 AES-256-GCM v10 加密）"""
import json
import sqlite3
import os
import shutil
import sys
import base64

try:
    import win32crypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:
    print(f"缺少依赖: {e}")
    print("pip install pywin32 cryptography")
    sys.exit(1)

# Edge 路径
LOCAL_STATE = os.path.expandvars(
    r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State"
)
LOGIN_DB = os.path.expandvars(
    r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data"
)

TEMP_DB = "edge_logins_temp.db"
OUTPUT_MD = "edge_passwords.md"


def get_encryption_key() -> bytes | None:
    """从 Local State 获取 AES 密钥（DPAPI 解密）"""
    if not os.path.exists(LOCAL_STATE):
        print(f"Local State 未找到: {LOCAL_STATE}")
        return None

    with open(LOCAL_STATE, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key")
    if not encrypted_key_b64:
        print("Local State 中未找到 encrypted_key")
        return None

    # Base64 解码 → 去掉 "DPAPI" 前缀（5 bytes）→ DPAPI 解密
    encrypted_key = base64.b64decode(encrypted_key_b64)
    # 去掉 "DPAPI" 前缀
    encrypted_key = encrypted_key[5:]

    try:
        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except Exception as e:
        print(f"DPAPI 解密密钥失败: {e}")
        return None


def decrypt_password_aes(blob: bytes, key: bytes) -> str:
    """解密 v10/v20 格式的密码 (AES-256-GCM)"""
    try:
        # v10/v20 格式: b"v10" 或 b"v20" (3 bytes) + nonce (12 bytes) + ciphertext
        prefix = blob[:3]
        if prefix not in (b"v10", b"v20"):
            return decrypt_password_dpapi(blob)
        nonce = blob[3:15]
        ciphertext = blob[15:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception:
        return "[解密失败]"


def decrypt_password_dpapi(blob: bytes) -> str:
    """解密旧版 DPAPI 格式"""
    try:
        return win32crypt.CryptUnprotectData(blob, None, None, None, 0)[1].decode("utf-8")
    except Exception:
        return "[解密失败]"


def extract_site(url: str) -> str:
    """从 URL 提取可读的站点名"""
    url = url.strip()
    for prefix in ("https://", "http://"):
        if url.startswith(prefix):
            url = url[len(prefix):]
            break
    if "/" in url:
        url = url.split("/")[0]
    return url


def main():
    # 获取 AES 密钥
    key = get_encryption_key()
    if not key:
        print("无法获取解密密钥，尝试纯 DPAPI 模式...")
        key = None

    # 复制数据库
    if not os.path.exists(LOGIN_DB):
        print(f"Edge 密码数据库未找到: {LOGIN_DB}")
        return

    shutil.copy2(LOGIN_DB, TEMP_DB)

    conn = sqlite3.connect(TEMP_DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute(
        "SELECT origin_url, username_value, password_value "
        "FROM logins "
        "WHERE blacklisted_by_user = 0 "
        "ORDER BY origin_url"
    )

    rows = cur.fetchall()
    conn.close()
    os.remove(TEMP_DB)

    # 解密 + 去重
    seen = set()
    entries = []
    decrypt_ok = 0
    decrypt_fail = 0

    for row in rows:
        site = extract_site(row["origin_url"])
        username = row["username_value"] or ""
        note = row["origin_url"]
        blob = row["password_value"]

        if key:
            password = decrypt_password_aes(blob, key)
        else:
            password = decrypt_password_dpapi(blob)

        if password == "[解密失败]" or not password:
            decrypt_fail += 1
            continue

        decrypt_ok += 1

        # 去重
        dedup_key = (site.lower(), username.lower())
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        entries.append((site, username, password, note))

    # 写入 Markdown
    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write("# Edge 浏览器保存的密码\n\n")
        f.write(f"> 导出时间: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"> 共 {len(entries)} 条记录（成功解密 {decrypt_ok} 条，失败 {decrypt_fail} 条）\n\n")
        f.write("| 网站 / 应用 | 用户名 | 密码 | 备注（原始URL） |\n")
        f.write("| --- | --- | --- | --- |\n")
        for site, user, pwd, note in entries:
            pwd_escaped = pwd.replace("|", "\\|")
            note_escaped = note.replace("|", "\\|")
            f.write(f"| {site} | {user} | {pwd_escaped} | {note_escaped} |\n")

    print(f"✅ 导出完成: {OUTPUT_MD}")
    print(f"   成功解密: {decrypt_ok} 条")
    print(f"   解密失败: {decrypt_fail} 条")
    print(f"   去重后:   {len(entries)} 条")
    print(f"   文件路径: {os.path.abspath(OUTPUT_MD)}")


if __name__ == "__main__":
    main()
