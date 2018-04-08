from flask import url_for, redirect, request
import flask_admin as admin
from flask_admin import helpers, expose
from flask_admin.contrib import sqla
from flask_admin.form import SecureForm
import flask_login as login

from app.forms import LoginForm


class MyAdminIndexView(admin.AdminIndexView):
    """ Customized Admin index class to handle user authentication """

    @expose('/')
    def index(self):
        if not login.current_user.is_authenticated:
            return redirect(url_for('.login_view'))
        return super(MyAdminIndexView, self).index()

    @expose('/login/', methods=('GET', 'POST'))
    def login_view(self):
        form = LoginForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = form.get_user()
            login.login_user(user)

        if login.current_user.is_authenticated:
            return redirect(url_for('.index'))
        self._template_args['form'] = form
        return super(MyAdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        login.logout_user()
        return redirect(url_for('.index'))


class MyModelView(sqla.ModelView):
    """ Custmized model view class to restrict access to
    authenticated users """

    form_base_class = SecureForm

    def is_accessible(self):
        return login.current_user.is_authenticated
