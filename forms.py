from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Optional, Length, EqualTo, Regexp

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    # password = PasswordField('Password', validators=[DataRequired()])
    # role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')])
    # first_name = StringField('First Name', validators=[DataRequired()])
    # last_name = StringField('Last Name', validators=[DataRequired()])
    # middle_name = StringField('Middle Name (Optional)', validators=[Optional()])
    # phone_or_email = StringField('Phone Number/Email', validators=[DataRequired(), Email()])
    # state_of_origin = StringField('State of Origin', validators=[DataRequired()])
    # lga = StringField('Local Government Area (LGA)', validators=[DataRequired()])
    # biometric_verification = BooleanField('Enable Biometric Verification')
    # hometown = StringField('Hometown', validators=[DataRequired(), Length(max=100)])
    # voters_card_number = StringField('Voter’s Card Number', validators=[DataRequired()])
    
    #Password validation: 8 characters with at least one letter and one number
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        # Regexp(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', message="Password must contain both letters and numbers.")
    ])
    # confirm_password = PasswordField('Confirm Password', validators=[
    #     DataRequired(),
    #     EqualTo('password', message="Passwords must match.")
    # ])
    
    submit = SubmitField('Register')


class AdminRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    # password = PasswordField('Password', validators=[DataRequired()])
    # role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')])
    # first_name = StringField('First Name', validators=[DataRequired()])
    # last_name = StringField('Last Name', validators=[DataRequired()])
    # middle_name = StringField('Middle Name (Optional)', validators=[Optional()])
    # phone_or_email = StringField('Phone Number/Email', validators=[DataRequired(), Email()])
    # state_of_origin = StringField('State of Origin', validators=[DataRequired()])
    # lga = StringField('Local Government Area (LGA)', validators=[DataRequired()])
    # biometric_verification = BooleanField('Enable Biometric Verification')
    # hometown = StringField('Hometown', validators=[DataRequired(), Length(max=100)])
    # voters_card_number = StringField('Voter’s Card Number', validators=[DataRequired()])
    
    #Password validation: 8 characters with at least one letter and one number
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        # Regexp(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', message="Password must contain both letters and numbers.")
    ])
    # confirm_password = PasswordField('Confirm Password', validators=[
    #     DataRequired(),
    #     EqualTo('password', message="Passwords must match.")
    # ])
    
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
