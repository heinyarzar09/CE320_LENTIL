from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.fields.simple import HiddenField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from app.models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('Student', 'Student'), ('GLA', 'GLA'), ('Lecturer', 'Lecturer')], validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RequestForm(FlaskForm):
    topic = SelectField('Topic', choices=[
        ('IDE', 'IDE'), ('compiling', 'Compiling'),
        ('libraries', 'Libraries'), ('subversion', 'Subversion'),
        ('Trac', 'Trac'), ('Java', 'Java'), ('Python', 'Python'),
        ('C', 'C'), ('assessment', 'Assessment'),
        ('course_material', 'Course Material'), ('suggestion', 'Suggestion')
    ], validators=[DataRequired()])
    urgency = SelectField('Urgency', choices=[
        ('I’m stuck', 'I’m stuck'),
        ('I can work around for now', 'I can work around for now'),
        ('Just for information', 'Just for information')
    ], validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    module = StringField('Module', default='CE320', validators=[DataRequired()])
    machine_position = StringField('Machine Position', validators=[DataRequired()])  # New field for machine position
    submit = SubmitField('Submit Request')

class MessageForm(FlaskForm):
    receiver = SelectField('To', coerce=int, validators=[DataRequired()])
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

class ClassMessageForm(FlaskForm):
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send to Class')

class AddSolutionForm(FlaskForm):
    pattern = StringField('Pattern', validators=[DataRequired()])
    solution_text = TextAreaField('Solution Text', validators=[DataRequired()])
    request_id = HiddenField('Request ID')
    submit = SubmitField('Add Solution')

class ClassMessageForm(FlaskForm):
    content = TextAreaField('Message Content', validators=[DataRequired()])
    submit = SubmitField('Send Message')