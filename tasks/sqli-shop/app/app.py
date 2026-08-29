"""Vulnerable shop: injectable /search and /product endpoints over sqlite (stdlib)."""

import json
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

FLAG = os.environ["FLAG"]
DB = "/tmp/shop.db"


def init_db() -> None:
    conn = sqlite3.connect(DB)
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, user TEXT, pass TEXT, role TEXT);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, stock INTEGER);
        CREATE TABLE secrets (id INTEGER PRIMARY KEY, note TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, uid INT, product INT, total REAL);
        INSERT INTO users VALUES (1,'admin','not-the-flag',  'admin'), (2,'carol','hunter2', 'user');
        INSERT INTO products VALUES
          (1,'USB-C hub 7-port', 39.99, 12),
          (2,'Mechanical keyboard 65%', 89.00, 5),
          (3,'4K webcam', 59.50, 0),
          (4,'USB desk lamp', 19.20, 40),
          (5,'Docking station', 149.00, 3),
          (6,'Cable organizer', 4.99, 200);
        INSERT INTO orders VALUES (1,2,1,39.99),(2,2,6,9.98),(3,1,5,149.00);
        """
    )
    conn.execute("INSERT INTO secrets VALUES (1, ?)", (FLAG,))
    conn.commit()
    conn.close()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: N802
        pass

    def _html(self, code: int, body: str) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        u = urlparse(self.path)
        q = parse_qs(u.query)
        conn = sqlite3.connect(DB)
        if u.path == "/":
            rows = conn.execute("SELECT id, name, price, stock FROM products").fetchall()
            items = "".join(
                f"<li>{r[1]} - ${r[2]:.2f} (stock {r[3]}) [<a href='/product?id={r[0]}'>view</a>]</li>"
                for r in rows
            )
            self._html(
                200,
                f"<h1>shop</h1><form action='/search'>Search: <input name='s'><input type='submit'></form><ul>{items}</ul>",
            )
        elif u.path == "/search":
            s = (q.get("s") or [""])[0]
            try:
                rows = conn.execute(
                    f"SELECT id, name, price, stock FROM products WHERE name LIKE '%{s}%'"
                ).fetchall()
            except sqlite3.Error as exc:
                return self._html(500, f"db error: {exc}")
            items = "".join(f"<li>{r}</li>" for r in rows)
            self._html(200, f"<h1>results for '{s}'</h1><ul>{items}</ul>")
        elif u.path == "/product":
            i = (q.get("id") or ["1"])[0]
            try:
                rows = conn.execute(
                    f"SELECT id, name, price, stock FROM products WHERE id = {i}"
                ).fetchall()
            except sqlite3.Error as exc:
                return self._html(500, f"db error: {exc}")
            self._html(200, f"<h1>product</h1><pre>{rows}</pre>")
        else:
            self._html(404, "not found")
        conn.close()


if __name__ == "__main__":
    init_db()
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
