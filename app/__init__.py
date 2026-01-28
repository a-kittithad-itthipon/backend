from flask import Flask
from .config import Config
from .extensions import bcrypt, jwt, mail
from .routes.auth import auth_bp


def create_app():
    app = Flask(__name__)

    # load configuration
    app.config.from_object(Config)

    # init extension
    bcrypt.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)

    # register blueprints
    app.register_blueprint(auth_bp)

    return app
