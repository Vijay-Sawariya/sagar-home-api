"""Exercise the real update handler with MySQL's changed-row semantics."""
import ast
import unittest
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path


class HTTPException(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        super().__init__(detail)


class Cursor:
    def __init__(self, exists, changed):
        self.exists = exists
        self.rowcount = changed
        self.queries = []

    def execute(self, query, values):
        self.queries.append((query, values))

    def fetchone(self):
        if self.queries[-1][0].startswith('SELECT id'):
            return {'id': 42} if self.exists else None
        return {'id': 42, 'status': 'Dismissed', 'due_date': '2026-09-18'}


def handler(cursor):
    class Connection:
        def cursor(self): return cursor
        def commit(self): pass

    @contextmanager
    def get_db():
        yield Connection()

    tree = ast.parse(Path(__file__).with_name('server.py').read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'update_reminder')
    node.decorator_list = []
    node.args.defaults = []
    scope = dict(get_db=get_db, ensure_action_assignment_column=lambda _: None,
                 datetime=datetime, HTTPException=HTTPException)
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'server.py', 'exec'), scope)
    return scope['update_reminder']


class ReminderUpdateTests(unittest.TestCase):
    def test_repeated_stop_succeeds(self):
        for role in ['admin', 'user']:
            with self.subTest(role=role):
                cursor = Cursor(exists=True, changed=0)
                result = handler(cursor)(42, {'status': 'Dismissed'}, {'id': 7, 'role': role})
                self.assertEqual(result['status'], 'Dismissed')
                if role == 'user':
                    self.assertIn('user_id = %s OR assigned_to = %s', cursor.queries[1][0])
                    self.assertEqual(cursor.queries[1][1], (42, 7, 7))

    def test_missing_or_inaccessible_reminder_still_returns_404(self):
        cursor = Cursor(exists=False, changed=0)
        with self.assertRaises(HTTPException) as error:
            handler(cursor)(42, {'status': 'Dismissed'}, {'id': 7, 'role': 'user'})
        self.assertEqual(error.exception.status_code, 404)
        self.assertEqual(len(cursor.queries), 2)

    def test_changed_update_succeeds(self):
        cursor = Cursor(exists=True, changed=1)
        self.assertEqual(handler(cursor)(42, {'status': 'Dismissed'}, {'id': 7, 'role': 'user'})['id'], 42)
        self.assertEqual(len(cursor.queries), 2)


if __name__ == '__main__':
    unittest.main()
