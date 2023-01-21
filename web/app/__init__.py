from flask import Flask
import os


app = Flask(__name__)

# Set up configuration
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
app.config["DEBUG"] = True if os.environ["FLASK_DEBUG"] == "1" else False


# Set up database
from flask_sqlalchemy import SQLAlchemy

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres@database/postgres"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# Set up user login
import flask_login as login

login_manager = login.LoginManager()
login_manager.init_app(app)


class User:
    def __init__(self, user):
        self.user = user

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.user.id


@login_manager.user_loader
def load_user(user_id):
    user = models.User.query.filter_by(id=int(user_id)).first()
    return User(user)


from app import views
