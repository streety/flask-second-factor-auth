import os

import bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, fields, form, validators

from app import models


class RegisterForm(FlaskForm):
    """Registration form with built in validation of unique username."""

    username = fields.StringField(validators=[validators.InputRequired()])
    password = fields.PasswordField(validators=[validators.InputRequired()])

    def validate_username(self, field):
        user = models.User.query.filter_by(username=self.username.data).first()
        if user != None:
            print(user)
            raise validators.ValidationError("Username already in use")


class LoginForm(FlaskForm):
    """Login form with built in validation of password."""

    username = fields.StringField(validators=[validators.InputRequired()])
    password = fields.PasswordField(validators=[validators.InputRequired()])

    def validate_password(self, field):
        self.user = models.User.query.filter_by(username=self.username.data).first()

        if self.user == None:
            raise validators.ValidationError("Invalid username or password")

        if (
            bcrypt.hashpw(self.password.data.encode("utf-8"), self.user.password_hash)
            != self.user.password_hash
        ):
            raise validators.ValidationError("Invalid username or password")


class AddTokenForm(FlaskForm):
    """Form to add a U2F token."""

    name = fields.StringField(validators=[validators.InputRequired()])
    response = fields.HiddenField(validators=[validators.InputRequired()])


class SignTokenForm(FlaskForm):
    """Sign in using a token"""

    response = fields.HiddenField(validators=[validators.InputRequired()])
