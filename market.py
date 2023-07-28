from xml.dom import registerDOMImplementation
from flask import Flask, render_template, redirect, request, url_for, flash
import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__)
app.secret_key = '123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'
db = SQLAlchemy(app)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

class RegistrationForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    
class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    contact_info = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    categories = db.Column(db.String(50), nullable=False)
    additional_item = db.Column(db.String(200))
    address = db.Column(db.String(200), nullable=False)
    eircode = db.Column(db.String(10), nullable=False)
    pickup_datetime = db.Column(db.DateTime, nullable=False)
    num_boxes = db.Column(db.Integer, nullable=False)
    
# Required callback for Flask-Login to load the current user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def homepage1():
    return render_template('home.html')

@app.route('/register' , methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Process the form data and register the user
        full_name = form.full_name.data
        email = form.email.data
        password = form.password.data

        # Check if user already exists in the database
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please use a different email.', 'error')
        else:
            # Create a new user and add it to the database
            new_user = User(full_name=full_name, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/dashboard')
def dashboard():
    # Render the user dashboard page
    return render_template('dashboard.html')

@app.route('/donations')
def donate():
    all_donations = Donation.query.all()
    return render_template('donations.html', donations=all_donations)

@app.route('/donate', methods=['GET', 'POST'])
def submit_donation():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        contact_info = request.form.get('contact_info')
        email = request.form.get('email')
        categories = request.form.getlist('categories')
        additional_item = request.form.get('additional_item')
        address = request.form.get('address')
        eircode = request.form.get('eircode')
        pickup_date = request.form.get('pickup_date')
        pickup_time = request.form.get('pickup_time')
        num_boxes = request.form.get('num_boxes')


        if not all([full_name, contact_info, email, categories, address, eircode, pickup_date, pickup_time, num_boxes]):
            flash('Please fill in all required fields', 'error')
        else:
            pickup_datetime = datetime.datetime.strptime(pickup_date + ' ' + pickup_time, '%Y-%m-%d %H:%M')
 
            
            # Check for uniqueness of email before adding the donation
            if not Donation.query.filter_by(email=email).first():


            # Create a new Donation object and save it to the database
                new_donation = Donation(
                full_name=full_name,
                contact_info=contact_info,
                email=email,
                categories=','.join(categories),
                additional_item=additional_item,
                address=address,
                eircode=eircode,
                pickup_datetime=pickup_datetime,
                num_boxes=int(num_boxes)
            )
            db.session.add(new_donation)
            db.session.commit()
            flash('Donation successfully submitted!', 'success')
            return redirect(url_for('donate'))
    return render_template('donate.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        # Process the login form data and check credentials
        email = form.email.data
        password = form.password.data

        # Validate user credentials against the database
        user = User.query.filter_by(email=email).first()
        if user and user.password == password:
            # Successful login
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()  # Log the user out
    flash('You have been logged out.', 'success')
    return redirect(url_for('homepage1'))

    # Flash a message to indicate successful logout (optional)
    flash('You have been logged out.', 'success')

    # Redirect the user to the homepage or login page
    return redirect(url_for('homepage1'))

@app.route('/communication')
def communication():
    return render_template('communication.html')

if __name__ == '__main__':
    # Create the database table
    with app.app_context():
        db.create_all()
