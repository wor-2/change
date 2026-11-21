import os, uuid
from functools import wraps
import psycopg2, psycopg2.extras
from dotenv import load_dotenv
load_dotenv()   # reads the .env file next to app.py
from flask import (Flask, g, request, session, redirect, url_for, render_template, flash, abort, send_from_directory)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import notify

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
UPLOAD_DIR = os.getenv("UPLOAD_DIR", os.path.join(os.path.dirname(__file__), "uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)
DSN = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/changemgmt")

TEAMS = ["Application Support", "Infrastructure", "Database", "Network", "Security", "Business Operations"]
ENVS = ["Development", "QA / UAT", "Production", "DR"]
TYPES = ["Standard", "Normal", "Emergency", "Major"]
ROLES_ALL = ["requester", "cab", "technical", "business", "approver", "admin"]
STATUS_LABEL = {"SUBMITTED": "Submitted", "ASSESSMENT": "Impact assessment", "PENDING_APPROVAL": "Pending approval",
                "APPROVED": "Approved - ready to execute", "REJECTED": "Rejected", "CHANGES_REQUESTED": "Changes requested",
                "COMPLETED": "Completed"}
# flow step (from the process diagram) each status is currently at
STEP_OF = {"CHANGES_REQUESTED": 2, "SUBMITTED": 4, "ASSESSMENT": 5, "PENDING_APPROVAL": 6, "APPROVED": 7, "COMPLETED": 8, "REJECTED": 8}
STEPS = ["Login", "Submit", "Confirm", "Triage", "Impact", "Approval", "Execution", "Notify"]
ACTION_ROLES = {"triage": {"cab", "admin"}, "assess": {"technical", "business", "cab", "admin"},
                "decide": {"approver", "cab", "admin"}, "execute": {"technical", "admin"}}
ACTION_STATUS = {"triage": "SUBMITTED", "assess": "ASSESSMENT", "decide": "PENDING_APPROVAL", "execute": "APPROVED"}

# ---------------------------------------------------------------- database
def db():
    if "db" not in g:
        g.db = psycopg2.connect(DSN, cursor_factory=psycopg2.extras.RealDictCursor)
    return g.db

@app.teardown_appcontext
def close_db(_):
    c = g.pop("db", None)
    if c: c.close()

def q(sql, args=(), one=False, commit=False):
    cur = db().cursor()
    cur.execute(sql, args)
    rows = (cur.fetchone() if one else cur.fetchall()) if cur.description else None
    if commit: db().commit()
    return rows

def init_db():
    with app.app_context():
        cur = db().cursor()
        cur.execute(open(os.path.join(os.path.dirname(__file__), "schema.sql")).read())
        db().commit()
        if not q("select 1 from users limit 1", one=True):
            demo = [("admin", "System Admin", "admin"), ("alice", "Alice (Business User)", "requester"),
                    ("cab1", "Carl (CAB Member)", "cab"), ("tech1", "Tara (Technical Lead)", "technical"),
                    ("biz1", "Bhavna (Business Owner)", "business"), ("appr1", "Arjun (Approver)", "approver")]
            for u, n, r in demo:
                q("insert into users(username,display_name,email,role,password_hash) values(%s,%s,%s,%s,%s)",
                  (u, n, f"{u}@example.com", r, generate_password_hash("password123")), commit=True)

# ---------------------------------------------------------------- auth (step 1)
def ad_login(username, password):
    from ldap3 import Server, Connection
    from ldap3.utils.conv import escape_filter_chars
    try:
        c = Connection(Server(os.getenv("AD_SERVER")), user=f"{username}@{os.getenv('AD_DOMAIN')}", password=password, auto_bind=True)
        c.search(os.getenv("AD_BASE_DN"), f"(sAMAccountName={escape_filter_chars(username)})", attributes=["displayName", "mail", "mobile"])
        e = c.entries[0] if c.entries else None
        return {"name": str(e.displayName) if e else username, "mail": str(e.mail) if e else None,
                "phone": str(e.mobile) if e and e.mobile else None}
    except Exception:
        return None

@app.before_request
def load_user():
    g.user = q("select * from users where id=%s", (session["uid"],), one=True) if session.get("uid") else None
    if not g.user and request.endpoint not in ("login", "static"):
        return redirect(url_for("login"))

def need_role(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if g.user["role"] not in roles: abort(403)
            return f(*a, **k)
        return w
    return deco

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form["username"].strip(), request.form["password"]
        user = q("select * from users where username=%s", (u,), one=True)
        if os.getenv("AD_ENABLED", "false").lower() == "true":
            info = ad_login(u, p)
            if info and not user:   # first AD login: create with least privilege (role-based access)
                user = q("insert into users(username,display_name,email,phone,role) values(%s,%s,%s,%s,'requester') returning *",
                         (u, info["name"], info["mail"], info["phone"]), one=True, commit=True)
            if not info: user = None
        elif not (user and user["password_hash"] and check_password_hash(user["password_hash"], p)):
            user = None
        if user:
            session["uid"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("Sign-in failed. Check your username and password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------------------------------------------------------- helpers
def available(cr):
    """The single workflow action the current user can take on this request (or None)."""
    u = g.user
    for act, st in ACTION_STATUS.items():
        if cr["status"] == st and u["role"] in ACTION_ROLES[act]:
            if act == "decide" and u["role"] == "approver" and cr["approver_id"] not in (None, u["id"]):
                continue
            return act
    if cr["status"] == "CHANGES_REQUESTED" and cr["requester_id"] == u["id"]:
        return "resubmit"

def load(cid):
    cr = q("""select c.*, r.display_name requester, r.email requester_email, a.display_name approver
              from change_requests c join users r on r.id=c.requester_id left join users a on a.id=c.approver_id
              where c.id=%s""", (cid,), one=True)
    if not cr: abort(404)
    if g.user["role"] == "requester" and cr["requester_id"] != g.user["id"]: abort(403)
    return cr

def save_files(cid, stage):
    for f in request.files.getlist("files"):
        if f and f.filename:
            name = secure_filename(f.filename)
            stored = f"{uuid.uuid4().hex}_{name}"
            f.save(os.path.join(UPLOAD_DIR, stored))
            q("insert into attachments(change_id,filename,stored_name,stage) values(%s,%s,%s,%s)", (cid, name, stored, stage), commit=True)

def log(cid, action, comment=""):
    q("insert into history(change_id,actor,action,comment) values(%s,%s,%s,%s)", (cid, g.user["display_name"], action, comment), commit=True)

def notify_all(cr_id, subject, text, whatsapp=False):
    """Step 3 / Step 8: tell requester, assigned approver and extra stakeholders."""
    cr = q("select * from change_requests where id=%s", (cr_id,), one=True)
    people = q("select email, phone from users where id in (%s,%s)", (cr["requester_id"], cr["approver_id"] or 0))
    emails = {p["email"] for p in people if p["email"]} | {e.strip() for e in (cr["stakeholders"] or "").split(",") if e.strip()}
    phones = {p["phone"] for p in people if p["phone"]} if whatsapp else set()
    msg = f"[{cr['change_no']}] {text}\nTitle: {cr['title']}\nStatus: {STATUS_LABEL[cr['status']]}\nApprover: {cr_approver(cr)}"
    for ch, rcpts, fn in (("email", emails, lambda r: notify.send_email(r, subject, msg)),
                          ("whatsapp", phones, lambda r: notify.send_whatsapp(r, msg))):
        for r in rcpts:
            try: st = fn(r)
            except Exception as e: st = f"FAILED: {e}"[:200]
            q("insert into notifications(change_id,channel,recipient,message,status) values(%s,%s,%s,%s,%s)", (cr_id, ch, r, msg, st), commit=True)

def cr_approver(cr):
    a = q("select display_name from users where id=%s", (cr["approver_id"],), one=True) if cr["approver_id"] else None
    return a["display_name"] if a else "-"

def move(cid, status, action, comment="", **fields):
    sets = ", ".join(f"{k}=%s" for k in fields)
    closed = ", closed_at=now()" if status in ("COMPLETED", "REJECTED") else ""
    q(f"update change_requests set status=%s, updated_at=now(){closed}{', ' + sets if sets else ''} where id=%s",
      (status, *fields.values(), cid), commit=True)
    log(cid, action, comment)
    final = status in ("COMPLETED", "REJECTED")
    notify_all(cid, f"Change update: {STATUS_LABEL[status]}", action, whatsapp=final)

# ---------------------------------------------------------------- pages
@app.route("/")
def dashboard():
    flt = request.args.get("status", "")
    sql, args = "select c.*, u.display_name requester from change_requests c join users u on u.id=c.requester_id where true", []
    if g.user["role"] == "requester": sql += " and requester_id=%s"; args.append(g.user["id"])
    if flt: sql += " and status=%s"; args.append(flt)
    rows = q(sql + " order by created_at desc", args)
    for r in rows: r["todo"] = bool(available(r))
    return render_template("dashboard.html", rows=rows, flt=flt)

@app.route("/new", methods=["GET", "POST"])
def new():   # steps 2 + 3
    if request.method == "POST":
        f = request.form
        need = ["title", "application", "environment", "change_type", "description", "planned_start", "planned_end"]
        missing = [k for k in need if not f.get(k, "").strip()]
        if missing: flash("Fill in all required fields: " + ", ".join(missing), "error")
        elif f["planned_end"] <= f["planned_start"]: flash("Planned end must be after planned start.", "error")
        else:
            cr = q("""insert into change_requests(change_no,title,application,environment,change_type,priority,description,
                      planned_start,planned_end,stakeholders,requester_id)
                      values('CHG-'||to_char(now(),'YYYY')||'-'||lpad(nextval('change_seq')::text,5,'0'),
                             %s,%s,%s,%s,%s,%s,%s,%s,%s,%s) returning *""",
                   (f["title"], f["application"], f["environment"], f["change_type"], f["priority"], f["description"],
                    f["planned_start"], f["planned_end"], f.get("stakeholders"), g.user["id"]), one=True, commit=True)
            save_files(cr["id"], "submit")
            log(cr["id"], "Change request submitted")
            notify_all(cr["id"], f"Change {cr['change_no']} submitted", "Your change request was submitted.")
            flash(f"Change request submitted. Your Change ID is {cr['change_no']}. A confirmation email was sent.", "ok")
            return redirect(url_for("detail", cid=cr["id"]))
    return render_template("new.html", ENVS=ENVS, TYPES=TYPES, f=request.form)

@app.route("/cr/<int:cid>")
def detail(cid):
    cr = load(cid)
    return render_template("detail.html", cr=cr, act=available(cr), STEPS=STEPS, step=STEP_OF[cr["status"]], TEAMS=TEAMS,
        approvers=q("select id, display_name from users where role in ('approver','cab') order by display_name"),
        files=q("select * from attachments where change_id=%s order by id", (cid,)),
        hist=q("select * from history where change_id=%s order by id desc", (cid,)))

@app.route("/cr/<int:cid>/<action>", methods=["POST"])
def act(cid, action):
    cr, f = load(cid), request.form
    if available(cr) != action: abort(403)
    back = redirect(url_for("detail", cid=cid))
    if action == "triage":      # step 4
        if f["decision"] == "return":
            if not f["triage_notes"].strip(): flash("Add a note explaining what the requester must fix.", "error"); return back
            move(cid, "CHANGES_REQUESTED", "Returned to requester at triage", f["triage_notes"], triage_notes=f["triage_notes"])
        else:
            if not (f.get("assigned_team") and f.get("approver_id")): flash("Choose a team and an approver.", "error"); return back
            move(cid, "ASSESSMENT", f"Triage complete - assigned to {f['assigned_team']}", f["triage_notes"],
                 assigned_team=f["assigned_team"], approver_id=int(f["approver_id"]), triage_notes=f["triage_notes"])
    elif action == "assess":    # step 5
        keys = ["business_impact", "technical_impact", "affected_services", "implementation_plan"]
        if not all(f.get(k, "").strip() for k in keys): flash("Complete all four assessment fields.", "error"); return back
        move(cid, "PENDING_APPROVAL", "Impact assessment completed", **{k: f[k] for k in keys})
    elif action == "decide":    # step 6
        d, c = f["decision"], f["comment"].strip()
        if d != "approve" and not c: flash("Add a comment when rejecting or requesting changes.", "error"); return back
        st = {"approve": "APPROVED", "reject": "REJECTED", "changes": "CHANGES_REQUESTED"}[d]
        move(cid, st, {"approve": "Approved", "reject": "Rejected", "changes": "Changes requested"}[d] + f" by {g.user['display_name']}", c,
             approval_comment=c, approver_id=g.user["id"] if g.user["role"] == "approver" else cr["approver_id"])
    elif action == "execute":   # step 7
        if not (f["execution_notes"].strip() and f.get("verified")):
            flash("Add execution notes and confirm the implementation was verified.", "error"); return back
        save_files(cid, "execution")
        move(cid, "COMPLETED", "Change executed and closed", f["execution_notes"], execution_notes=f["execution_notes"], verified=True)
    elif action == "resubmit":
        if f.get("description", "").strip():
            q("update change_requests set description=%s where id=%s", (f["description"], cid), commit=True)
        save_files(cid, "resubmit")
        move(cid, "SUBMITTED", "Requester resubmitted the change")
    flash("Saved. Notifications were sent.", "ok")
    return back

@app.route("/files/<int:fid>")
def download(fid):
    a = q("select * from attachments where id=%s", (fid,), one=True) or abort(404)
    load(a["change_id"])
    return send_from_directory(UPLOAD_DIR, a["stored_name"], as_attachment=True, download_name=a["filename"])

@app.route("/notifications")
@need_role("admin", "cab")
def notifications():
    return render_template("notifications.html", rows=q("""select n.*, c.change_no from notifications n
        left join change_requests c on c.id=n.change_id order by n.id desc limit 200"""))

@app.route("/users", methods=["GET", "POST"])
@need_role("admin")
def users():
    if request.method == "POST":
        q("update users set role=%s, email=%s, phone=%s where id=%s",
          (request.form["role"], request.form["email"], request.form["phone"] or None, request.form["id"]), commit=True)
        flash("User updated.", "ok")
    return render_template("users.html", rows=q("select * from users order by username"), ROLES=ROLES_ALL)

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
