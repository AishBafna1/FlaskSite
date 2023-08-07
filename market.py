from flask import Flask, render_template, redirect, request, url_for, flash
import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_login import LoginManager,UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_bcrypt import generate_password_hash, check_password_hash




from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__)
app.secret_key = '123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)


# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Replace 'login' with the route function name for your login page

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
    
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    
    def set_password(self, password):
        self.password = generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
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
    
class UserQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f'<UserQuestion {self.id}>'

    
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
            # Hash the password using Flask-Bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            # Create a new user and add it to the database
            new_user = User(full_name=full_name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    # Render the user dashboard page
    return render_template('dashboard.html')

@app.route('/about')
def about():
    # Render the user dashboard page
    return render_template('about.html')

@app.route('/donations')
@login_required
def donate():
    # Retrieve all donations associated with the currently logged-in user
    user_donations = Donation.query.filter_by(email=current_user.email).all()    
    return render_template('donations.html', donations=user_donations)

@app.route('/donate', methods=['GET', 'POST'])
@login_required
def submit_donation():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        contact_info = request.form.get('contact_info')
        email = request.form.get('email')
        categories = request.form.getlist('categories')
        additional_item = request.form.get('additional_item')
        address = request.form.get('address')
        eircode = request.form.get('eircode')
        pickup_datetime_str = request.form.get('pickup_datetime')

        num_boxes = request.form.get('num_boxes')

        if (full_name and contact_info and email and categories and address and eircode and pickup_datetime_str):
            pickup_datetime = datetime.datetime.strptime(pickup_datetime_str,'%Y-%m-%d %H:%M')

            # Create a new Donation object and save it to the database
            donation = Donation(
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
            db.session.add(donation)
            db.session.commit()

            flash('Donation successfully submitted!', 'donation_success')  # Flash the success message
            return redirect(url_for('donate'))  # Redirect to the donations page
        else:
            flash('Please fill in all required fields', 'error')  # Flash an error message for incomplete form

    return render_template('donate.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        # Process the login form data and check credentials
        email = form.email.data
        password = form.password.data

        # Check if the entered credentials belong to the admin user
        if email == 'admin@gmail.com':
            admin_user = User.query.filter_by(email=email).first()
            if admin_user and bcrypt.check_password_hash(admin_user.password, password):
                flash('Admin login successful!', 'login_success')
                login_user(admin_user)  # Log in the admin user
                return redirect(url_for('admin_dashboard'))  # Redirect to the admin dashboard

        # Validate regular user credentials against the database
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            # Successful login
            flash('Login successful!', 'login_success')
            login_user(user)  # Log in the regular user
            if current_user.is_authenticated:
                return redirect(url_for('dashboard'))  # Redirect to the regular user's dashboard
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()  # Log the user out
    flash('You have been logged out.', 'success')
    return redirect(url_for('homepage1'))

@app.route('/admin')
@login_required
def admin_dashboard():
    # Fetch all donations from the database and pass them to the template
    all_donations = Donation.query.all()
    return render_template('admin.html', donations=all_donations)

@app.route('/communication', methods=['GET', 'POST'])
def communication():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Create a new UserQuestion object and save it to the database
        user_question = UserQuestion(name=name, email=email, message=message)
        db.session.add(user_question)
        db.session.commit()

        flash('Your question has been submitted. Thank you!', 'success')
        return redirect(url_for('communication'))

    return render_template('communication.html')

@app.route('/admin_questions')
@login_required
def admin_questions():
    # Retrieve all user questions from the database
    user_questions = UserQuestion.query.all()

    return render_template('admin_questions.html', questions=user_questions)


if __name__ == '__main__':
    # Create the database table
    with app.app_context():
        db.create_all()
        

