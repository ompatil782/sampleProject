"""
vuln_demo.py - intentionally vulnerable demonstration app

Vulnerabilities:
  - SQL Injection (/find?q=<term>)
  - Command Injection (/run?cmd=<command>)
  - Path Traversal / insecure file handling (/getfile?name=<filename>)
  - Insecure deserialization of pickle data (/deserialize) - POST raw bytes

USAGE (local only):
  1. Install Flask:
       pip install Flask
  2. Run:
       python vuln_demo.py
  3. Visit:
       http://127.0.0.1:5000/find?q=alice
       http://127.0.0.1:5000/run?cmd=whoami
       http://127.0.0.1:5000/getfile?name=../../somefile
       Use curl to POST pickled data to /deserialize (only for testing in lab)
"""

from flask import Flask, request, g, send_file, abort, Response
import sqlite3
import os
import subprocess
import pickle

DB_PATH = "vuln_demo.db"
FILES_DIR = os.path.join(os.getcwd(), "files")  # directory with sample files

app = Flask(__name__)

# --- Database helpers -------------------------------------------------
def get_db():
    if getattr(g, "_db", None) is None:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g._db = conn
    return g._db

@app.before_first_request
def init_db():
    # create DB and seed data
    if not os.path.exists(DB_PATH):
        db = sqlite3.connect(DB_PATH)
        c = db.cursor()
        c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
        c.execute("INSERT INTO users (username, email) VALUES ('alice','alice@example.com')")
        c.execute("INSERT INTO users (username, email) VALUES ('bob','bob@example.com')")
        db.commit()
        db.close()
    # ensure files directory exists and has a sample file
    if not os.path.exists(FILES_DIR):
        os.makedirs(FILES_DIR, exist_ok=True)
    sample_path = os.path.join(FILES_DIR, "sample.txt")
    if not os.path.exists(sample_path):
        with open(sample_path, "w", encoding="utf-8") as f:
            f.write("This is a safe sample file.\n")

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

# ---------------------------------------------------------------------
# Vulnerable endpoint: SQL Injection (string formatting)
# e.g. /find?q=alice or /find?q=' OR '1'='1
# ---------------------------------------------------------------------
@app.route("/find")
def find_user():
    q = request.args.get("q", "")
    db = get_db()
    # WARNING: vulnerable string concatenation -> SQL injection
    sql = "SELECT id, username, email FROM users WHERE username = '%s'" % q
    # A secure approach uses parameterized queries:
    # cur = db.execute("SELECT id, username, email FROM users WHERE username = ?", (q,))
    cur = db.execute(sql)  # intentionally vulnerable
    rows = cur.fetchall()
    if not rows:
        return f"No results for: {q}"
    out = "<h3>Results</h3><ul>"
    for r in rows:
        out += "<li>%s (%s)</li>" % (r["username"], r["email"])
    out += "</ul>"
    return out

# ---------------------------------------------------------------------
# Vulnerable endpoint: Command Injection via subprocess with shell=True
# e.g. /run?cmd=dir  or /run?cmd=whoami
# ---------------------------------------------------------------------
@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd", "")
    if not cmd:
        return "Provide ?cmd=..."
    # WARNING: using shell=True with user input is dangerous (command injection)
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5, universal_newlines=True)
    except Exception as e:
        output = f"Error running command: {e}"
    # return raw output (this may reveal sensitive info)
    return "<pre>%s</pre>" % output

# ---------------------------------------------------------------------
# Vulnerable endpoint: Path traversal / insecure file access
# e.g. /getfile?name=sample.txt  or /getfile?name=../somefile
# ---------------------------------------------------------------------
@app.route("/getfile")
def get_file():
    name = request.args.get("name", "")
    if not name:
        return "Provide ?name=..."
    # WARNING: naive join without sanitization allows path traversal
    requested_path = os.path.join(FILES_DIR, name)
    # A secure approach would validate filename and enforce a strict whitelist
    if not os.path.exists(requested_path):
        return "File not found: %s" % requested_path
    # Danger: returning arbitrary files from disk
    return send_file(requested_path, as_attachment=False)

# ---------------------------------------------------------------------
# Vulnerable endpoint: Insecure deserialization using pickle
# POST raw pickle bytes to /deserialize
# WARNING: loading pickle from untrusted source can execute arbitrary code
# ---------------------------------------------------------------------
@app.route("/deserialize", methods=["POST"])
def insecure_deserialize():
    data = request.get_data()
    if not data:
        return "POST raw pickle bytes in request body"
    try:
        # VERY DANGEROUS: pickle.loads can execute arbitrary code from crafted pickle
        obj = pickle.loads(data)
    except Exception as e:
        return f"Failed to deserialize: {e}"
    return f"Deserialized object: {repr(obj)}"

# Safe test root
@app.route("/")
def index():
    return (
        "<h2>vuln_demo</h2>"
        "<ul>"
        "<li>/find?q=&lt;username&gt;  (SQLi)</li>"
        "<li>/run?cmd=&lt;command&gt;  (Command Injection)</li>"
        "<li>/getfile?name=&lt;filename&gt;  (Path traversal)</li>"
        "<li>POST raw pickle bytes to /deserialize (Insecure deserialization)</li>"
        "</ul>"
    )


if __name__ == "__main__":
    # Run only on localhost and debug mode for testing (do NOT use this in prod)
    app.run(host="127.0.0.1", port=5000, debug=True)
