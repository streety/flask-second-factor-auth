from app import app, db, load_user
from flask import render_template, session, url_for, redirect, flash
import flask_login
from u2flib_server.u2f import (begin_registration, begin_authentication,
                               complete_registration, complete_authentication)
import json

from app import forms
from app import models

app_id = 'https://u2f-demo.local'


@app.route('/')
def index():
    return render_template('index.html')
    
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = forms.RegisterForm()
    if form.validate_on_submit():
        user = models.User(username = form.username.data, 
                           password = form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Registration complete", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        # User has supplied correct credentials
        # Store info in session and pass to 2FA check
        session['valid_credentials_supplied'] = True
        session['user'] = form.user.id
        flash("Username/password correct", "success")
        return redirect(url_for('select_2fa'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    flask_login.logout_user()
    flash("Logout complete", "success")
    return redirect(url_for('index'))

@app.route('/select-2fa', methods=['GET', 'POST'])
def select_2fa():
    if not session.get('valid_credentials_supplied', False):
        return redirect(url_for('login'))
    user = models.User.query.filter_by(id=session['user']).first()
    if len(user.u2f_credentials.all()) == 0:
        return redirect(url_for('add_2fa'))
    keys = user.u2f_credentials.all()
    return render_template('select_2fa.html', keys=keys, user=user)


@app.route('/validate-2fa/<name>', methods=['GET', 'POST'])
def validate_2fa(name):
    form = forms.SignTokenForm()
    if form.validate_on_submit():
        errorCode = json.loads(form.response.data)['errorCode']
        if errorCode != 0:
            flash("Token authentication failed", "error")
            return redirect(url_for('select_2fa'))
        device, c, t = complete_authentication(session['u2f_sign'],
                                              form.response.data, app_id)
        if t != 1:
            flash("Token authentication failed", "error")
            return redirect(url_for('select_2fa'))
        # Log in the user
        user = load_user(session['user'])
        flask_login.login_user(user)
        flash("Login complete", "success")
        return redirect(url_for('index'))
    key = models.U2FCredentials.query.filter_by(owner=session['user'],
                                               name=name).first()
    sign = begin_authentication(app_id, [key.device])
    session['u2f_sign'] = sign.json
    challenge = sign['challenge']
    registeredKeys = json.loads(sign['registeredKeys'][0])
    version = registeredKeys['version']
    keyHandle = registeredKeys['keyHandle']

    return render_template('validate_2fa.html', challenge=challenge,
                          version=version,
                          keyHandle=keyHandle,
                          app_id=app_id,
                          form=form,
                          key=key)


@app.route('/add-2fa', methods=['GET', 'POST'])
def add_2fa():
    form = forms.AddTokenForm()
    if form.validate_on_submit():
        # Complete 2FA registration
        registered_device = complete_registration(session['u2f_enroll'],
                                            form.response.data)[0].json
        user = models.User.query.filter_by(id=session['user']).first()
        u2f_cred = models.U2FCredentials(name = form.name.data,
                                         owner = user.id,
                                         device = registered_device)
        db.session.add(u2f_cred)
        db.session.commit()
        flash("Authentication token added", "success")
        return redirect(url_for('login'))
    # Start 2FA registration
    enroll = begin_registration(app_id, [])
    session['u2f_enroll'] = enroll.json
    challenge = enroll.data_for_client['registerRequests'][0]['challenge']
    return render_template('add_2fa.html', 
                           challenge = challenge, 
                           appId = app_id,
                           version = "U2F_V2",
                           form=form)
