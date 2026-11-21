# Change Management Portal (Flask + PostgreSQL)

Implements the 8-step Change Management Process Flow.

| Step | Where |
|---|---|
| 1 User login (Active Directory, role-based) | `/login`, `AD_ENABLED=true` uses LDAP bind; demo mode uses local users |
| 2 Submit change request | `/new` (fields, attachments, dates, unique Change ID `CHG-YYYY-00001`) |
| 3 Submit & confirm | validation, save, confirmation message + email |
| 4 Review & triage (CAB/admin) | accept + assign team/approver, or return to requester |
| 5 Impact assessment (technical/business) | business, technical, services, implementation plan |
| 6 Approval workflow (approver/CAB) | approve / reject / request changes + comments |
| 7 Change execution (technical) | execution notes, evidence, verification, close |
| 8 Notify user | Email (SMTP) + WhatsApp (Twilio); all attempts logged at `/notifications` |

## Run with Docker (easiest)
    docker compose up --build        # open http://localhost:5000

## Run without Docker
    createdb changemgmt
    python -m venv venv && source venv/bin/activate
    pip install -r requirements.txt
    export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/changemgmt
    python app.py                    # tables and demo users are created automatically

## Demo logins (password `password123`)
admin (admin) · alice (requester) · cab1 (cab) · tech1 (technical) · biz1 (business) · appr1 (approver)

Try it: log in as alice and submit a change; cab1 triages (assign team + appr1); tech1 or biz1 completes the
assessment; appr1 approves; tech1 executes and closes. Admin manages roles and phone numbers at `/users`.

## Production notes
Copy `.env.example` to `.env`, set `SECRET_KEY`, `AD_*`, `SMTP_*`, `TWILIO_*`. AD users are created as `requester`
on first login; an admin promotes them. Serve behind HTTPS (gunicorn is included).
