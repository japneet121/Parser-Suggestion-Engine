from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email

csrf = CSRFProtect()

class ContactForm(FlaskForm):
    json = StringField('JSON', validators=[DataRequired('Please enter some data')])
    submit = SubmitField("Submit")