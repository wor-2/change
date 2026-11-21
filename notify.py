"""Step 8 - Notify user: email + WhatsApp (Twilio). Every attempt is logged in the notifications table."""
import os, smtplib, base64, urllib.parse, urllib.request
from email.message import EmailMessage


def send_email(to, subject, body):
    host = os.getenv("SMTP_HOST")
    if not host:
        return "LOGGED (SMTP not configured)"
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = os.getenv("MAIL_FROM", "changes@example.com"), to, subject
    msg.set_content(body)
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", 587)), timeout=15) as s:
        s.starttls()
        if os.getenv("SMTP_USER"):
            s.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD", ""))
        s.send_message(msg)
    return "SENT"


def send_whatsapp(phone, body):
    sid, token = os.getenv("TWILIO_SID"), os.getenv("TWILIO_TOKEN")
    if not (sid and token):
        return "LOGGED (Twilio not configured)"
    data = urllib.parse.urlencode({"From": os.getenv("TWILIO_WHATSAPP_FROM"), "To": f"whatsapp:{phone}", "Body": body}).encode()
    req = urllib.request.Request(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json", data=data)
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{sid}:{token}".encode()).decode())
    urllib.request.urlopen(req, timeout=15)
    return "SENT"
