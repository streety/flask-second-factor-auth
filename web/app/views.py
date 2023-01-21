import json
import os

import fido2.features
import flask_login
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)
from flask import flash, redirect, render_template, session, url_for

from app import app, db, forms, load_user, models

rp_id = os.environ["AUTHN_ID"]
expected_origin = os.environ["AUTHN_ORIGIN"]

fido2.features.webauthn_json_mapping.enabled = True
rp = PublicKeyCredentialRpEntity(name=os.environ["AUTHN_NAME"], id=rp_id)
fido_server = Fido2Server(rp)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = forms.RegisterForm()
    if form.validate_on_submit():
        user = models.User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Registration complete", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        # User has supplied correct credentials
        # Store info in session and pass to 2FA check
        session["valid_credentials_supplied"] = True
        session["user"] = form.user.id
        flash("Username/password correct", "success")
        return redirect(url_for("select_2fa"))
    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    flask_login.logout_user()
    flash("Logout complete", "success")
    return redirect(url_for("index"))


@app.route("/select-2fa", methods=["GET", "POST"])
def select_2fa():
    if not session.get("valid_credentials_supplied", False):
        return redirect(url_for("login"))
    user = models.User.query.filter_by(id=session["user"]).first()
    if len(user.u2f_credentials.all()) == 0:
        return redirect(url_for("add_2fa"))
    keys = user.u2f_credentials.all()
    return render_template("select_2fa.html", keys=keys, user=user)


@app.route("/validate-2fa/<name>", methods=["GET", "POST"])
def validate_2fa(name):
    form = forms.SignTokenForm()
    key = models.U2FCredentials.query.filter_by(
        owner=session["user"], name=name
    ).first()
    device = _restore_credential_data(key.device)
    if form.validate_on_submit():
        response = json.loads(form.response.data)
        try:
            result = fido_server.authenticate_complete(
                session["webauthn_challenge"],
                [
                    device,
                ],
                response,
            )
        except:
            flash("Token authentication failed", "error")
            return redirect(url_for("select_2fa"))
        # Log in the user
        user = load_user(session["user"])
        flask_login.login_user(user)
        flash("Login complete", "success")
        return redirect(url_for("index"))
    key = models.U2FCredentials.query.filter_by(
        owner=session["user"], name=name
    ).first()
    device = _restore_credential_data(key.device)
    options, state = fido_server.authenticate_begin(
        [
            device,
        ]
    )
    session["webauthn_challenge"] = state
    # session['u2f_sign'] = sign.json
    return render_template(
        "validate_2fa.html",
        form=form,
        key=key,
        authentication_options=json.dumps(dict(options)),
    )


@app.route("/add-2fa", methods=["GET", "POST"])
def add_2fa():
    rp_name = "Jonathan Street personal site"
    form = forms.AddTokenForm()
    user = models.User.query.filter_by(id=session["user"]).first()
    if form.validate_on_submit():
        auth_data = fido_server.register_complete(
            session["webauthn_challenge"], json.loads(form.response.data)
        )
        cred_data = _store_credential_data(auth_data.credential_data)
        # Complete 2FA registration
        u2f_cred = models.U2FCredentials(
            name=form.name.data, owner=user.id, device=cred_data
        )
        db.session.add(u2f_cred)
        db.session.commit()
        flash("Authentication token added", "success")
        return redirect(url_for("login"))
    # Start 2FA registration
    options, state = fido_server.register_begin(
        PublicKeyCredentialUserEntity(
            id=b"user_id",
            name=user.username,
            display_name=user.username,
        ),
        [],
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )
    options = dict(options)
    session["webauthn_challenge"] = state
    return render_template(
        "add_2fa.html",
        registration_options=json.dumps(dict(options)),
        form=form,
    )


def _store_credential_data(cred):
    return cred.hex()


def _restore_credential_data(cred):
    return AttestedCredentialData.fromhex(cred)
