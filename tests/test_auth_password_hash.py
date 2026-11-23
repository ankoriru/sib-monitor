"""Вход в панель: загрузка bcrypt-хеша из переменных окружения и проверка Basic Auth."""
import base64
import os
import unittest
from unittest import mock

import bcrypt
from fastapi import HTTPException

import app

PASSWORD = "NewPass2026X"
HASH = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()
HASH_B64 = base64.b64encode(HASH.encode()).decode()


def _load(env):
    with mock.patch.dict(os.environ, env, clear=False):
        for key in ("AUTH_PASSWORD_HASH", "AUTH_PASSWORD_HASH_B64"):
            if key not in env:
                os.environ.pop(key, None)
        return app._load_auth_password_hash()


class LoadHashTests(unittest.TestCase):
    def test_b64_variable_is_preferred(self):
        value, source, err = _load({"AUTH_PASSWORD_HASH_B64": HASH_B64, "AUTH_PASSWORD_HASH": "broken"})
        self.assertEqual((value, source, err), (HASH, "AUTH_PASSWORD_HASH_B64", ""))

    def test_plain_hash_still_supported_and_trimmed(self):
        for raw in (HASH, f"  {HASH}\n", f'"{HASH}"', f"'{HASH}'"):
            with self.subTest(raw=raw):
                self.assertEqual(_load({"AUTH_PASSWORD_HASH": raw})[0], HASH)

    def test_mangled_dollar_hash_is_reported(self):
        mangled = HASH.replace("$", "")  # как если бы платформа «съела» знаки $
        value, source, err = _load({"AUTH_PASSWORD_HASH": mangled})
        self.assertEqual(value, "")
        self.assertIn("bcrypt", err)

    def test_bad_base64_is_reported(self):
        value, _, err = _load({"AUTH_PASSWORD_HASH_B64": "@@@"})
        self.assertEqual(value, "")
        self.assertIn("base64", err)

    def test_missing_hash_is_reported(self):
        self.assertEqual(_load({})[0], "")


class CheckAuthTests(unittest.TestCase):
    def _call(self, user, password):
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode()
        request = mock.Mock()
        request.headers = {"Authorization": f"Basic {token}"}
        response = mock.Mock()
        with mock.patch.object(app, "AUTH_USERNAME", "sibur"), \
             mock.patch.object(app, "AUTH_PASSWORD_HASH", HASH):
            return app.check_auth(request, response, None), response

    def test_correct_password_sets_cookie(self):
        ok, response = self._call("sibur", PASSWORD)
        self.assertTrue(ok)
        response.set_cookie.assert_called_once()

    def test_wrong_password_reprompts_browser(self):
        for user, pwd in (("sibur", "wrong"), ("other", PASSWORD), ("sibur", "пароль")):
            with self.subTest(user=user, pwd=pwd):
                with self.assertRaises(HTTPException) as ctx:
                    self._call(user, pwd)
                self.assertEqual(ctx.exception.status_code, 401)
                self.assertIn("WWW-Authenticate", ctx.exception.headers)

    def test_non_ascii_password_works(self):
        cyr = "Пароль2026"
        cyr_hash = bcrypt.hashpw(cyr.encode(), bcrypt.gensalt(rounds=4)).decode()
        token = base64.b64encode(f"sibur:{cyr}".encode("utf-8")).decode()
        request = mock.Mock(headers={"Authorization": f"Basic {token}"})
        with mock.patch.object(app, "AUTH_USERNAME", "sibur"), \
             mock.patch.object(app, "AUTH_PASSWORD_HASH", cyr_hash):
            self.assertTrue(app.check_auth(request, mock.Mock(), None))


class GeneratorTests(unittest.TestCase):
    def test_generator_output_round_trips(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("mk", "scripts/make_auth_hash.py")
        mk = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mk)
        value, source, err = _load({"AUTH_PASSWORD_HASH_B64": mk.make_value(PASSWORD)})
        self.assertEqual(err, "")
        self.assertTrue(bcrypt.checkpw(PASSWORD.encode(), value.encode()))


class AdminPasswordTests(unittest.TestCase):
    def test_no_admin_hash_in_source(self):
        src = open(app.__file__, encoding="utf-8").read()
        self.assertNotRegex(src, r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")
        self.assertNotIn("flvby", src)

    def test_admin_hash_loaded_from_own_variables(self):
        env = {"ADMIN_PASSWORD_HASH_B64": HASH_B64}
        with mock.patch.dict(os.environ, env):
            os.environ.pop("ADMIN_PASSWORD_HASH", None)
            self.assertEqual(app._load_auth_password_hash("ADMIN_PASSWORD_HASH"),
                             (HASH, "ADMIN_PASSWORD_HASH_B64", ""))

    def test_admin_password_check(self):
        with mock.patch.object(app, "ADMIN_PASSWORD_HASH", HASH):
            self.assertTrue(app._admin_password_ok(PASSWORD))
            self.assertFalse(app._admin_password_ok("wrong"))
            self.assertFalse(app._admin_password_ok(None))

    def test_admin_locked_without_hash(self):
        with mock.patch.object(app, "ADMIN_PASSWORD_HASH", ""):
            self.assertFalse(app._admin_password_ok(PASSWORD))
            request = mock.Mock(headers={"X-Admin-Auth": PASSWORD})
            with self.assertRaises(HTTPException):
                app.admin_auth(request, mock.Mock(), None)

    def test_admin_and_dashboard_hashes_are_independent(self):
        other = bcrypt.hashpw(b"AdminOnly1", bcrypt.gensalt(rounds=4)).decode()
        with mock.patch.object(app, "ADMIN_PASSWORD_HASH", other), \
             mock.patch.object(app, "AUTH_PASSWORD_HASH", HASH):
            self.assertFalse(app._admin_password_ok(PASSWORD))
            self.assertTrue(app._admin_password_ok("AdminOnly1"))


if __name__ == "__main__":
    unittest.main()
