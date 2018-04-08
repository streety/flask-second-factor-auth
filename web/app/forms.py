import os
import bcrypt
from wtforms import form, fields, validators
from flask_wtf import Form
from wtforms import TextAreaField, StringField, validators

from app import models


class RegisterForm(Form):
    """ Registration form with built in validation of unique username. """
    username = fields.TextField(validators=[validators.required()])
    password = fields.PasswordField(validators=[validators.required()])
    
    def validate_username(self, field):
        user = models.User.query.filter_by(username=self.username.data).first()
        if user != None:
            print(user)
            raise validators.ValidationError('Username already in use')


class LoginForm(Form):
    """ Login form with built in validation of password. """

    username = fields.TextField(validators=[validators.required()])
    password = fields.PasswordField(validators=[validators.required()])

    def validate_password(self, field):
        self.user = models.User.query.filter_by(username=self.username.data).first()
        
        if self.user == None:
            raise validators.ValidationError('Invalid username or password')

        if bcrypt.hashpw(self.password.data.encode('utf-8'),
                    self.user.password_hash) != \
                self.user.password_hash:
            raise validators.ValidationError('Invalid username or password')


class AddTokenForm(Form):
    """ Form to add a U2F token. """

    name = fields.TextField(validators=[validators.required()])
    response = fields.HiddenField(validators=[validators.required()])


class SignTokenForm(Form):
    """ Sign in using a token """

    response = fields.HiddenField(validators=[validators.required()])

