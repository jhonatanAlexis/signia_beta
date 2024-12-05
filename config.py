import os 
from dotenv import load_dotenv
import cloudinary

load_dotenv()

class Config:
    MONGO_URI = os.getenv("MONGO_URI")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET")

class ConfigGmail:
    MAIL_SERVER = os.getenv("GMAIL_SERVER")
    MAIL_PORT = int(os.getenv("GMAIL_PORT"))
    MAIL_USE_TLS = os.getenv("GMAIL_USE_TLS") == 'True'
    MAIL_USERNAME = os.getenv("GMAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("GMAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("GMAIL_DEFAULT_SENDER")

class CloudConfig:
    CLOUD_NAME= os.getenv("CLOUD_NAME")
    API_KEY= os.getenv("API_KEY")
    API_SECRET= os.getenv("API_SECRET")