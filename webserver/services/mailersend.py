import os
import dotenv

dotenv.load_dotenv(dotenv_path="./services/.env")
from mailersend import emails

API_KEY = os.getenv("API_KEY")
EMAIL_FROM = os.getenv("email")
print(API_KEY)
print(EMAIL_FROM)

mailer = emails.NewEmail(API_KEY)

def send_email(recipient_email: str, subject: str, text_content: str):
    mail_body = {}

    mail_from = {"name": "Your Company Name", "email": EMAIL_FROM}
    recipients = [{"name": "Recipient", "email": recipient_email}]
    reply_to = [{"name": "Reply", "email": "reply@example.com"}]

    mailer.set_mail_from(mail_from, mail_body)
    mailer.set_mail_to(recipients, mail_body)
    mailer.set_subject(subject, mail_body)
    mailer.set_html_content(text_content, mail_body)
    mailer.set_reply_to(reply_to, mail_body)

    mailer.send(mail_body)
