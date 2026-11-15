import smtplib
from email.message import EmailMessage
from app.core.config import settings

def email_is_configured() -> bool:
    return bool(settings.smtp_host and settings.mail_from)

def send_account_email(recipient: str, subject: str, body: str) -> None:
    if not email_is_configured():
        raise RuntimeError("SMTP não configurado.")
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.mail_from
    message["To"] = recipient
    message.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
        if settings.smtp_starttls:
            server.starttls()
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password or "")
        server.send_message(message)
