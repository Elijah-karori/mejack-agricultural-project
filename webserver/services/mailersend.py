import os
from dotenv import load_dotenv
import smtplib

load_dotenv()
def send_email(recipient_email, subject, body):
  smtp_email = os.getenv("SMTP_USERNAME")
  smtp_password = os.environ.get("SMTP_PASSWORD")
  sender_email=os.getenv("sender_email")
  
  
  print(smtp_email)
  print(smtp_password)
  
  message = f"""\
  Subject: {subject}
  
  From: {sender_email}
  {body}"""
  try:
      with smtplib.SMTP("smtp.mailgun.org", 587)         as server:
          server.login(smtp_email,smtp_password)
          server.sendmail(sender_email,       
  recipient_email, message)
      print("Email sent successfully.")
  except Exception as e:
          print(f"An error occurred while sending           email: {e}")



send_email("blakkarori@gmail.com","test","test")