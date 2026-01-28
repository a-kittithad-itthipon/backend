from os import getenv
from datetime import timedelta


class Config:
    SECRET_KEY = getenv("SECRET_KEY")

    # JWT CONFIG
    JWT_SECRET_KEY = getenv("JWT_SECRET_KEY")
    JWT_DECODE_LEEWAY = timedelta(minutes=5)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=10)

    # MAIL
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = getenv("MAIL_USERNAME")
    MAIL_PASSWORD = getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = getenv("MAIL_USERNAME")

    # OTHERS
    BASE_PATH = getenv("BASE_PATH")
