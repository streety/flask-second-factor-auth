from flask import session
from sqlalchemy import or_
import bcrypt

from app import db

from datetime import datetime


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(140), index=True, unique=True, )
    joined = db.Column(db.DateTime, )
    password_hash = db.Column(db.Binary(60), )
    u2f_credentials = db.relationship('U2FCredentials', backref='user', lazy='dynamic', )

    def __init__(self, username, password, joined=None):
        self.username = username
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        if joined is None:
            joined = datetime.now()
        self.joined = joined

    def __repr__(self):
        return '<User %r>' % (self.username)


class U2FCredentials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.Text, )
    date_added = db.Column(db.DateTime, )
    device = db.Column(db.Text, )


    def __init__(self, owner, name, device, date_added=None):
        self.owner = owner
        self.name = name
        self.device = device
        if date_added == None:
            date_added = datetime.now()
        self.date_added = date_added


    def __repr__(self):
        return '<U2FCredentials %r>' % (self.id)
