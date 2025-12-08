from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField, SelectMultipleField, HiddenField, IntegerField, widgets
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Regexp
from .models import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must start with a letter and can only contain letters, numbers, dots or underscores')
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long'),
        Regexp('(?=.*\d)(?=.*[a-z])(?=.*[A-Z])', message='Password must include at least one uppercase letter, one lowercase letter, and one number')
    ])
    password2 = PasswordField('Confirm Password', validators=[
        DataRequired(), 
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')
            
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')
        
        # Check if email domain is allowed
        if email.data:
            domain = email.data.split('@')[-1].lower()
            allowed_domains = ['bt.com', 'thbs.com']
            if domain not in allowed_domains:
                raise ValidationError('Registration is only allowed for BT and THBS employees. Please use your company email address.')
            
class TwoFactorForm(FlaskForm):
    token = StringField('Authentication Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message='Authentication code must be 6 digits'),
        Regexp('^\d{6}$', message='Authentication code must be 6 digits')
    ])
    submit = SubmitField('Verify')

class SetupTwoFactorForm(FlaskForm):
    token = StringField('Authentication Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message='Authentication code must be 6 digits'),
        Regexp('^\d{6}$', message='Authentication code must be 6 digits')
    ])
    submit = SubmitField('Enable 2FA')

class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()

class InterestSelectionForm(FlaskForm):
    interests = MultiCheckboxField('Interests', coerce=int)
    submit = SubmitField('Save Interests')

class UserApprovalForm(FlaskForm):
    action = HiddenField(validators=[DataRequired()])
    user_id = HiddenField(validators=[DataRequired()])
    submit = SubmitField('Submit')

class CourseForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[DataRequired()])
    cover_image_url = StringField('Cover Image URL', validators=[Length(max=500)])
    interests = MultiCheckboxField('Interests', coerce=int)
    submit = SubmitField('Save Course')

class LessonForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    content = TextAreaField('Content', validators=[DataRequired()])
    content_type = SelectField('Content Type', choices=[
        ('text', 'Text Only'),
        ('video', 'Video Only'),
        ('mixed', 'Text and Video')
    ], default='text')
    video_url = StringField('Video URL', validators=[Length(max=500)])
    order = IntegerField('Order', default=0)
    submit = SubmitField('Save Lesson')

class InterestForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    submit = SubmitField('Save Interest')

class UserInterestAccessForm(FlaskForm):
    user_id = HiddenField(validators=[DataRequired()])
    interest_id = HiddenField(validators=[DataRequired()])
    action = HiddenField(validators=[DataRequired()])
    submit = SubmitField('Update Access')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must start with a letter and can only contain letters, numbers, dots or underscores')
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password', validators=[
        Regexp('(?=.*\d)(?=.*[a-z])(?=.*[A-Z])', 0, 'Password must include at least one uppercase letter, one lowercase letter, and one number')
    ])
    new_password2 = PasswordField('Confirm New Password', validators=[
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Update Profile')


class ForumTopicForm(FlaskForm):
    title = StringField('Title', validators=[
        DataRequired(),
        Length(min=5, max=200, message='Title must be between 5 and 200 characters')
    ])
    content = TextAreaField('Content', validators=[
        DataRequired(),
        Length(min=10, message='Content must be at least 10 characters')
    ])
    course_id = HiddenField('Course ID')
    submit = SubmitField('Post Topic')


class ForumReplyForm(FlaskForm):
    content = TextAreaField('Reply', validators=[
        DataRequired(),
        Length(min=2, message='Reply must be at least 2 characters')
    ])
    submit = SubmitField('Post Reply')

class ApiKeyForm(FlaskForm):
    openai_api_key = PasswordField('OpenAI API Key', validators=[
        DataRequired(),
        Length(min=20, message='API key should be at least 20 characters long')
    ])
    submit = SubmitField('Save API Key')
