#!/usr/bin/env python3
"""
使用 PBKDF2-SHA256 生成密码哈希供插入数据库使用。
用法:
  python password.py --password secret
或交互式:
  python password.py
"""
import argparse
import getpass
from passlib.hash import pbkdf2_sha256

def gen_hash(pw: str) -> str:
    # pbkdf2_sha256 不受 72 字节限制，兼容性好
    return pbkdf2_sha256.hash(pw)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--password", "-p", help="要哈希的明文密码（不安全，推荐交互式输入）")
    args = p.parse_args()

    if args.password:
        pw = args.password
    else:
        pw = getpass.getpass("Password: ")
        pw_confirm = getpass.getpass("Confirm: ")
        if pw != pw_confirm:
            print("两次输入不一致，退出。")
            return

    hashed = gen_hash(pw)
    print(hashed)
    print("\n-- 示例 SQL（请替换 username 与 roles）")
    print("INSERT INTO users (username, password_hash, full_name, roles) VALUES ('admin', '{}', 'Administrator', '[\"admin\"]');".format(hashed))

if __name__ == "__main__":
    main()