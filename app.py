from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from forms import RegistrationForm, LoginForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_pymongo import PyMongo

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config["MONGO_URI"] = "mongodb://chinedu_daniel:okenna1234@localhost:27017/chinedu_flask"

# Initialize MongoDB
mongo = PyMongo(app)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simulated vote storage (for demo purposes)
# users = {"user": {"username": "user", "password": "pass", "has_voted": False}}
votes = {'option1': 0, 'option2': 0}

# In-memory store for users
users = {}
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "adminpassword"

class User(UserMixin):
    def __init__(self, id, username, password, has_voted=False):
        self.id = id
        self.username = username
        self.password = password
        self.has_voted = has_voted  # Track if the user has voted

    @staticmethod
    def get(user_id):
        user_data = mongo.db.users.find_one({"username": user_id})
        print("User data retrieved from database:", user_data)  # Debug statement
        if user_data:
            return User(
                username=user_data['username'],
                password=user_data['password'],
                has_voted=user_data.get('has_voted', False)
            )
        return None


@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({"username": user_id})
    if user_data:
        return User(
            id=user_data['username'],
            username=user_data['username'],
            password=user_data['password'],
            has_voted=user_data.get('has_voted', False)
        )
    return None

@app.route('/')
def index():
    # Redirect to home page if the user is logged in, else go to login
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if form.username.data in users:
            flash('Username already exists!', 'danger')
        else:
            new_user = User(
                id=form.username.data,
                username=form.username.data,
                password=form.password.data
            )
            users[form.username.data] = new_user  # Store the User object directly
            mongo.db.users.insert_one({
                "username": form.username.data,
                "password": form.password.data,
                "has_voted": False  # Set default has_voted status
            })  # Ensure user is also stored in MongoDB
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print("Form submitted")  # Debug statement
        user_data = mongo.db.users.find_one({"username": form.username.data})
        if form.username.data == ADMIN_USERNAME and form.password.data == ADMIN_PASSWORD:
            print("Admin login detected")  # Debug statement
            admin_user = User(id=ADMIN_USERNAME, username=ADMIN_USERNAME, password=ADMIN_PASSWORD)
            login_user(admin_user)
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))


        if user_data and user_data['password'] == form.password.data:
            print("Normal user login detected")  # Debug statement
            user = User(user_data['username'], user_data['password'], user_data.get('has_voted', False))
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('vote'))
        else:
            print("Form errors:", form.errors)  # Debug statement
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    print("User authenticated:", current_user.is_authenticated)  # Debug statement
    print("Current user:", current_user.username)  # Debug statement
    return render_template('dashboard.html', username=current_user.username)


@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    if current_user.has_voted:
        flash("You've already voted!", "warning")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        choice = request.form.get('choice')
        
        # Update the vote count and user's vote status
        if choice in votes:
            votes[choice] += 1
            current_user.has_voted = True  # Update user's has_voted attribute
            # Update the user in the users dictionary with the new has_voted status
            users[current_user.id].has_voted = True
            # Update the user's has_voted status in the database as well
            mongo.db.users.update_one(
                {"username": current_user.username},
                {"$set": {"has_voted": True}}
            )
            flash(f"Your vote for {choice} has been recorded!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid vote option!", "danger")
    
    return render_template('vote.html', options=votes.keys())


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():

# Debugging to confirm if the user is logged in
    print("Accessing admin dashboard with user:", current_user.username)
    print("Is authenticated?", current_user.is_authenticated)

    if current_user.username != ADMIN_USERNAME:
        flash('Access denied!', 'danger')
        print("Non-admin user attempted access")  # Debug statement
        return redirect(url_for('dashboard'))
    
    print("Admin user accessed admin dashboard")  # Debug statement
    return render_template('admin_dashboard.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
