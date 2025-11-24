from flask_mail import Mail, Message
from flask import current_app

mail: Mail = Mail()

def send_confirmation_email(to_email: str, token: str) -> None:
    subject: str = "Confirm your registration"
    body: str = f"Hello,\n\nPlease confirm your account by using this token:\n{token}\n\nThank you!"
    
    try:
        msg: Message = Message(subject=subject, recipients=[to_email], body=body)
        mail.send(msg)
        print(f"📩 Confirmation email sent to {to_email}")
    except Exception as e:
        current_app.logger.error(f"❌ Failed to send email to {to_email}: {e}")
