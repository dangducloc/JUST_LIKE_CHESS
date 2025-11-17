from flask_mail import Mail, Message
from flask import current_app

mail = Mail()

def send_confirmation_email(to_email: str, token: str) -> None:
    confirm_url = f"http://localhost:5000/api/auth/confirm/{token}"
    subject = "Confirm your registration"
    body = f"Hello,\n\nPlease confirm your account by clicking the link:\n{confirm_url}\n\nThank you!"
    
    try:
        msg = Message(subject=subject, recipients=[to_email], body=body)
        mail.send(msg)
        print(f"📩 Confirmation email sent to {to_email}")
    except Exception as e:
        current_app.logger.error(f"❌ Failed to send email to {to_email}: {e}")
