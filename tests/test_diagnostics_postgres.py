"""Optional integration tests in a disposable schema, never DATABASE_URL.

SIB_MONITOR_TEST_DSN='dbname=sib_monitor_diagnostics_test' \
    python -m unittest discover -s tests -v
"""
import os
import unittest
import uuid
from unittest.mock import patch

import psycopg2
from psycopg2 import sql

import app


@unittest.skipUnless(os.getenv("SIB_MONITOR_TEST_DSN"), "isolated PostgreSQL DSN not set")
class PostgreSQLDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.dsn = os.environ["SIB_MONITOR_TEST_DSN"]
        self.schema = "test_diagnostics_" + uuid.uuid4().hex
        self.admin = psycopg2.connect(self.dsn)
        self.admin.autocommit = True
        with self.admin.cursor() as cur:
            cur.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.addCleanup(self.cleanup_schema)
        with self.connection() as conn:
            with conn.cursor() as cur:
                # Previous table shapes, before the additive migration.
                cur.execute("""
                    CREATE TABLE latest_status (
                        site TEXT PRIMARY KEY, status INTEGER, response_time REAL,
                        ssl_days INTEGER, domain_days INTEGER, ssl_chain_valid BOOLEAN,
                        timestamp TIMESTAMP
                    );
                    CREATE TABLE logs (
                        site TEXT, status INTEGER, response_time REAL, ssl_days INTEGER,
                        domain_days INTEGER, ssl_chain_valid BOOLEAN,
                        timestamp TIMESTAMP DEFAULT NOW()
                    );
                    CREATE TABLE checks_agg (
                        site TEXT NOT NULL, bucket TIMESTAMP NOT NULL,
                        checks_count INTEGER DEFAULT 1, status_200_count INTEGER DEFAULT 0,
                        down_sec INTEGER DEFAULT 0, avg_response_time REAL,
                        min_response_time REAL, max_response_time REAL,
                        last_ssl_days INTEGER, last_domain_days INTEGER,
                        last_ssl_chain_valid BOOLEAN, PRIMARY KEY(site, bucket)
                    );
                    INSERT INTO latest_status VALUES
                        ('example.org', 200, 0.2, 4, 99, TRUE, NOW());
                """)
        conn.close()

    def connection(self):
        return psycopg2.connect(self.dsn, options=f"-csearch_path={self.schema}")

    def cleanup_schema(self):
        with self.admin.cursor() as cur:
            cur.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(self.schema)))
        self.admin.close()

    def read(self, query):
        conn = self.connection()
        try:
            with conn.cursor() as cur:
                cur.execute(query)
                return cur.fetchall()
        finally:
            conn.close()

    def migrate(self):
        conn = self.connection()
        try:
            with conn:
                with conn.cursor() as cur:
                    app._ensure_check_error_column(cur)
        finally:
            conn.close()

    def test_migration_preserves_existing_rows_and_is_repeatable(self):
        before = self.read("SELECT * FROM latest_status")
        self.migrate()
        self.migrate()
        after = self.read("""
            SELECT site, status, response_time, ssl_days, domain_days,
                   ssl_chain_valid, timestamp FROM latest_status
        """)
        self.assertEqual(before, after)
        self.assertEqual(self.read("SELECT check_error FROM latest_status"), [(None,)])

    def test_real_batch_sql_persists_reason_clears_recovery_and_preserves_ssl(self):
        self.migrate()
        for status, elapsed, reason in [(0, 8.12, "DNS: адрес не найден"),
                                       (200, 0.25, None)]:
            # HTTP snapshot is stale: certificate was already updated to 4 days.
            rows = [("example.org", status, elapsed, 5, 100, False, reason)]
            with patch.object(app, "get_db_connection", side_effect=self.connection), \
                    patch.object(app, "batch_buffer", rows):
                app._flush_batch_unlocked()
            saved = self.read("""
                SELECT status, response_time, check_error, ssl_days, domain_days,
                       ssl_chain_valid FROM latest_status
            """)[0]
            self.assertEqual(saved[0], status)
            self.assertAlmostEqual(saved[1], elapsed, places=4)
            self.assertEqual(saved[2:], (reason, 4, 99, True))
        self.assertEqual(self.read("SELECT COUNT(*) FROM logs"), [(2,)])
        self.assertEqual(self.read("""
            SELECT SUM(checks_count), SUM(status_200_count) FROM checks_agg
        """), [(2, 1)])


if __name__ == "__main__":
    unittest.main()
