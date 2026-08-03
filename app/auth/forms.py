import re
from flask_wtf import FlaskForm
from flask_babel import _, lazy_gettext as _l
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
import sqlalchemy as sa
from app import db
from app.models import User

def validate_strong_password(password, username=None):
    password = password.strip()

    if len(password) < 8:
        raise ValidationError(
            _('Password must be at least 8 characters long.')
        )

    if len(password) > 64:
        raise ValidationError(
            _('Password cannot be longer than 64 characters.')
        )

    if " " in password:
        raise ValidationError(
            _('Password cannot contain spaces.')
        )

    if not re.search(r"[A-Z]", password):
        raise ValidationError(
            _('Password must contain at least one uppercase letter.')
        )

    if not re.search(r"[a-z]", password):
        raise ValidationError(
            _('Password must contain at least one lowercase letter.')
        )

    if not re.search(r"\d", password):
        raise ValidationError(
            _('Password must contain at least one number.')
        )

    if not re.search(r"[!@#$%^&*()_\-+=\[\]{};:'\",.<>?/\\|`~]", password):
        raise ValidationError(
            _('Password must contain at least one special character.')
        )

    if username and username.lower() in password.lower():
        raise ValidationError(
            _('Password cannot contain your username.')
        )
    
class LoginForm(FlaskForm):
    username = StringField(_l('Username'), validators=[DataRequired()])
    password = PasswordField(_l('Password'), validators=[DataRequired()])
    remember_me = BooleanField(_l('Remember Me'))
    submit = SubmitField(_l('Sign In'))

class RegistrationForm(FlaskForm):
    username = StringField(
        _l('Username'),
        validators=[DataRequired()]
    )

    email = StringField(
        _l('Email'),
        validators=[DataRequired(), Email()]
    )

    password = PasswordField(
        _l('Password'),
        validators=[DataRequired()]
    )

    password2 = PasswordField(
        _l('Repeat Password'),
        validators=[
            DataRequired(),
            EqualTo('password')
        ]
    )

    submit = SubmitField(_l('Register'))

    def validate_password(self, password):
        validate_strong_password(
            password.data,
            self.username.data
        )

    def validate_username(self, username):
        user = db.session.scalar(sa.select(User).where(
            User.username == username.data))
        if user is not None:
            raise ValidationError(_('Please use a different username.'))

    def validate_email(self, email):
        user = db.session.scalar(sa.select(User).where(
            User.email == email.data))
        if user is not None:
            raise ValidationError(_('Please use a different email address.'))


class ResetPasswordRequestForm(FlaskForm):
    email = StringField(_l('Email'), validators=[DataRequired(), Email()])
    submit = SubmitField(_l('Request Password Reset'))

class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        _l('Password'),
        validators=[DataRequired()]
    )

    password2 = PasswordField(
        _l('Repeat Password'),
        validators=[
            DataRequired(),
            EqualTo('password')
        ]
    )

    submit = SubmitField(_l('Request Password Reset'))

    def validate_password(self, password):
        validate_strong_password(password.data)