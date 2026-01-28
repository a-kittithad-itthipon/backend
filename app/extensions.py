from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_mail import Mail

bcrypt = Bcrypt()
jwt = JWTManager()
mail = Mail()
