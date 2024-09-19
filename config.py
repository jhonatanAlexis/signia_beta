import os 
from dotenv import load_dotenv

load_dotenv()

class Config:
    MONGO_URI = os.getenv("MONGO_URI")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET")
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER")

class ConfigGmail:
    MAIL_SERVER = os.getenv("GMAIL_SERVER")
    MAIL_PORT = int(os.getenv("GMAIL_PORT"))
    MAIL_USE_TLS = os.getenv("GMAIL_USE_TLS") == 'True'
    MAIL_USERNAME = os.getenv("GMAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("GMAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("GMAIL_DEFAULT_SENDER")

class ConfigOutlook:
    MAIL_SERVER = os.getenv("OUTLOOK_SERVER")
    MAIL_PORT = int(os.getenv("OUTLOOK_PORT"))
    MAIL_USE_TLS = os.getenv("OUTLOOK_USE_TLS") == 'True'
    MAIL_USERNAME = os.getenv("OUTLOOK_USERNAME")
    MAIL_PASSWORD = os.getenv("OUTLOOK_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("OUTLOOK_DEFAULT_SENDER")