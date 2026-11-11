# DELIBERATELY VULNERABLE - test fixture for the VAPT scanner. Do not run or deploy.
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, render_template_string, request, session

from config import SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY


def db():
    return sqlite3.connect("app.db")


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    # SQL injection: user input formatted straight into the query
    query = "SELECT id FROM users WHERE username = '%s' AND password = '%s'" % (username, pw_hash)
    row = db().execute(query).fetchone()
    if row:
        session["user_id"] = row[0]
        return redirect(request.args.get("next", "/"))  # open redirect
    return "invalid", 401


@app.route("/search")
def search():
    term = request.args.get("q", "")
    cur = db().cursor()
    cur.execute(f"SELECT name FROM products WHERE name LIKE '%{term}%'")
    return {"results": cur.fetchall()}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # OS command injection
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    os.system("echo pinged " + host)
    return out


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "1+1")))


@app.route("/import", methods=["POST"])
def import_data():
    obj = pickle.loads(request.get_data())
    cfg = yaml.load(request.form.get("config", ""), Loader=yaml.Loader)
    return {"ok": True, "type": str(type(obj)), "cfg": str(cfg)}


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text


@app.route("/invoices/<int:invoice_id>")
def invoice(invoice_id):
    # IDOR: any logged-in user can read any invoice; ownership is never checked
    if "user_id" not in session:
        return "login required", 401
    row = db().execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    return {"invoice": row}


@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    # Auth bypass: trusts a client-controlled header instead of the session
    if request.headers.get("X-Role") == "admin":
        db().execute("DELETE FROM users WHERE id = ?", (request.form["id"],))
        return "deleted"
    return "forbidden", 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
