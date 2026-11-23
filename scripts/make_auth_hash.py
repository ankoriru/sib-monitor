#!/usr/bin/env python3
"""Готовит значение переменной с bcrypt-хешем пароля в base64 для sib-monitor.

Запуск: python scripts/make_auth_hash.py
Пароль вводится скрыто. Результат вставьте в Amvera → «Переменные»:
  AUTH_PASSWORD_HASH_B64  — вход в панель (Basic Auth);
  ADMIN_PASSWORD_HASH_B64 — вход во вкладку «Управление».
Затем перезапустите приложение.
"""
import base64
import getpass
import sys

import bcrypt


def make_value(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    return base64.b64encode(hashed).decode("ascii")


def main():
    password = getpass.getpass("Новый пароль: ")
    if not password or password != getpass.getpass("Повторите пароль: "):
        sys.exit("Пароли пустые или не совпадают")
    print("\nЗначение для AUTH_PASSWORD_HASH_B64 или ADMIN_PASSWORD_HASH_B64:")
    print(make_value(password))


if __name__ == "__main__":
    main()
