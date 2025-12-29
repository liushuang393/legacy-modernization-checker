#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
脆弱性テスト用Pythonファイル（本番使用禁止）
Semgrep / Gitleaks 検出対象
"""

import os
import pickle
import subprocess
import sqlite3
import yaml
import hashlib
import random

# [VULN-060] ハードコードされた認証情報
API_KEY = "sk-proj-1234567890abcdefghijklmnop"
DATABASE_PASSWORD = "admin123"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# [VULN-061] SQLインジェクション
def get_user(username: str) -> dict:
    """ユーザー名で検索（脆弱）"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # 危険：文字列フォーマットでSQL構築
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


# [VULN-062] コマンドインジェクション（shell=True）
def run_command(user_input: str) -> str:
    """コマンド実行（脆弱）"""
    # 危険：shell=Trueでユーザー入力を実行
    result = subprocess.run(f"echo {user_input}", shell=True, capture_output=True)
    return result.stdout.decode()


# [VULN-063] os.system使用
def ping_host(host: str) -> int:
    """ホストにping（脆弱）"""
    # 危険：os.systemでユーザー入力を実行
    return os.system(f"ping -c 1 {host}")


# [VULN-064] 安全でないデシリアライズ（pickle）
def load_data(data: bytes) -> object:
    """データ読み込み（脆弱）"""
    # 危険：信頼できないpickleデータのデシリアライズ
    return pickle.loads(data)


# [VULN-065] 安全でないYAML読み込み
def load_config(yaml_content: str) -> dict:
    """YAML設定読み込み（脆弱）"""
    # 危険：yaml.load()はコード実行可能
    return yaml.load(yaml_content, Loader=yaml.Loader)


# [VULN-066] 弱いハッシュアルゴリズム（MD5）
def hash_password_md5(password: str) -> str:
    """パスワードハッシュ（脆弱）"""
    # 危険：MD5は暗号学的に安全ではない
    return hashlib.md5(password.encode()).hexdigest()


# [VULN-067] 弱いハッシュアルゴリズム（SHA1）
def hash_password_sha1(password: str) -> str:
    """パスワードハッシュ（脆弱）"""
    # 危険：SHA1は暗号学的に安全ではない
    return hashlib.sha1(password.encode()).hexdigest()


# [VULN-068] 安全でない乱数生成
def generate_token() -> str:
    """トークン生成（脆弱）"""
    # 危険：randomモジュールはセキュリティ用途に不適切
    return str(random.randint(100000, 999999))


# [VULN-069] eval使用
def calculate(expression: str) -> float:
    """計算式評価（脆弱）"""
    # 危険：任意のコード実行可能
    return eval(expression)


# [VULN-070] exec使用
def run_user_code(code: str) -> None:
    """ユーザーコード実行（脆弱）"""
    # 危険：任意のコード実行可能
    exec(code)


# [VULN-071] パストラバーサル
def read_file(filename: str) -> str:
    """ファイル読み込み（脆弱）"""
    # 危険：パス検証なし
    filepath = f"/data/{filename}"
    with open(filepath, 'r') as f:
        return f.read()


# [VULN-072] assert文をセキュリティチェックに使用
def check_admin(user: dict) -> bool:
    """管理者チェック（脆弱）"""
    # 危険：assertは-Oオプションで無効化される
    assert user.get('role') == 'admin', "Not admin"
    return True


if __name__ == "__main__":
    print("This file contains security vulnerabilities for testing purposes only!")

