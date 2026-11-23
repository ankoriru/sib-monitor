#!/usr/bin/env python3
"""Готовит значение переменной AUTH_PASSWORD_HASH_B64 для входа в панель sib-monitor.

Запуск: python scripts/make_auth_hash.py
Пароль вводится скрыто. Результат (bcrypt-хеш в base64) вставьте в Amvera →
«Переменные» → AUTH_PASSWORD_HASH_B64 и перезапустите приложение.
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
    print("\nAUTH_PASSWORD_HASH_B64 =")
    print(make_value(password))


if __name__ == "__main__":
    main()
