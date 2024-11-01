import os
from functools import wraps
from flask import Flask, render_template, session, redirect, url_for, flash, request, jsonify
from forms import RegistrationForm, LoginForm, AdminRegistrationForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_pymongo import PyMongo
# from .data import nigerian_states_lgas
from data import states_and_lgas  # Ensure this line correctly imports
from random import randint  # Import to generate a random validation number
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SESSION_TYPE'] = 'filesystem'  # or another suitable type like 'redis' if available
app.config['SESSION_USE_SIGNER'] = True  # To add additional security to cookies
app.config["MONGO_URI"] = "mongodb://chinedu_daniel:okenna1234@localhost:27017/chinedu_flask"
app.secret_key = os.urandom(24)  # Replace with a secure secret key

# Initialize MongoDB
mongo = PyMongo(app)

login_manager = LoginManager()
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
    def __init__(self, id, username, password, has_voted=False, first_name=None, last_name=None, middle_name=None, phone_or_email=None, state=None, lga=None, hometown=None):
        self.id = id
        self.username = username
        self.password = password
        self.has_voted = has_voted
        self.first_name = first_name
        self.last_name = last_name
        self.middle_name = middle_name
        self.phone_or_email = phone_or_email
        self.state = state
        self.lga = lga
        self.hometown = hometown

    @staticmethod
    def get(user_id):
        user_data = mongo.db.users.find_one({"username": user_id})
        print("User data retrieved from database:", user_data)  # Debug statement
        if user_data:
            return User(
                id=user_data['username'],
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
    return User.get(user_id)

@app.route('/')
def main_dashboard():
    return render_template('main_dashboard.html')

# Dummy validation function for credentials (replace with actual logic)
def validate_registration(credentials):
    # Add your logic to check if the credentials are correct
    # For example, check if the username already exists, etc.
    if credentials['username'] == "valid_user":  # Replace with actual validation
        return True
    return False

@app.route('/register', methods=['GET', 'POST']) 
def register():
    print("Print registration route")
    form = RegistrationForm()

    if form.validate_on_submit():
        print("Form is valid")
        # Check if form submission is valid (successful registration attempt)
        username = form.username.data
        password = form.password.data
        # role = form.role.data

         # Check if the user already exists
        # existing_user = users_collection.find_one({'username': username})
        existing_user = mongo.db.users.find_one({"username": username})
        if existing_user:
            print("There is existing user")
            flash("Username already exists. Please choose a different one.", "danger")
            return redirect(url_for('login'))

        # Create a new user document
        user_data = {
            'username': username,
            'password': generate_password_hash(password),  # Hash the password before saving
            'role': 'user'  # Default role for new users; change to 'admin' as needed
        }

        print("Got to line 110")
        # Insert the new user into the database
        mongo.db.users.insert_one(user_data)
        flash("Registration successful! Please log in.", "success")
        print("Got to line 115")
        return redirect(url_for('login'))  # Redirect to the login page

    return render_template('register.html', form=form)  # Render registration form

@app.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    print("Print registration route")
    form = AdminRegistrationForm()

    if form.validate_on_submit():
        print("Form is valid")
        # Check if form submission is valid (successful registration attempt)
        username = form.username.data
        password = form.password.data
        # role = form.role.data

         # Check if the user already exists
        # existing_user = users_collection.find_one({'username': username})
        existing_user = mongo.db.users.find_one({"username": username})
        if existing_user:
            print("There is existing user")
            flash("Username already exists. Please choose a different one.", "danger")
            return redirect(url_for('login'))

        # Create a new user document
        user_data = {
            'username': username,
            'password': generate_password_hash(password),  # Hash the password before saving
            'role': 'admin'  # Default role for new users; change to 'admin' as needed
        }

        print("Got to line 110")
        # Insert the new user into the database
        mongo.db.users.insert_one(user_data)

        # Clear session and set session variables
        session.clear()  # Clear old session data

        # Automatically log in the new admin user
        session['user_role'] = 'admin'
        session['username'] = username

        # Debug print for session
        print("Session variables:", session)

        flash("Admin account created successfully!", "success")
        print("Redirecting to admin_dashboard")

        return redirect(url_for('admin_dashboard'))  # Redirect directly to the admin dashboard


    return render_template('create_admin.html', form=form)  # Render form to create admin


# from flask import session, flash, redirect, render_template, request, url_for
# from werkzeug.security import check_password_hash

@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Login Form")
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        print("form is valid")

        # Attempt to find user in the database
        user = mongo.db.users.find_one({'username': username})
        print('user')
        if user:
            # Debugging output
            print("User found in the database:", user)
            session['user_role'] = user.get('role')
            session['user_id'] = str(user['_id'])
            # Check if password matches
            print(user.get("password"))
            print(password)
            if check_password_hash(user['password'], password):
                print("Password correct")
            # # if check_password_hash(user['password'], password):
            #     # session['user_role'] = user['role']
            #     # session['user_id'] = str(user['_id'])
                flash("Login successful!", "success")

                if user.get("role") == "user":
                    # Debug role and redirection
                    # return redirect(url_for('user_dashboard'))
                    print("user")
                elif user.get("role") == "admin":
                    # return redirect(url_for('admin_dashbord'))
                    print("admin")
                else:
                    return redirect(url_for('main_dashboard'))
                        # Redirect to the appropriate dashboard
                        # if session.get('user_role') == 'user':
                        #     print("Redirecting to user_dashboard")
                        #     return redirect(url_for('user_dashboard'))
                        # elif session.get('user_role') == 'admin':
                        #     print("Redirecting to admin_dashboard")
                        #     return redirect(url_for('admin_dashboard'))
            else:
                flash("Incorrect password.", "danger")
        else:
            flash("Username not found.", "danger")
            
            # If login fails, redirect to main dashboard
            # print("Login failed, redirecting to main_dashboard")
            # return redirect(url_for('main_dashboard'))

    return render_template('login.html', form=form)


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        flash("Access denied. Admins only.", "danger")
    # Ensure only admins can access this route
    if session.get('user_role') != 'admin':
        flash("Access denied!", "danger")
        return redirect(url_for('login'))
    
    # Retrieve candidates and count total validated candidates
    candidates = candidates_collection.find()
    total_validated_candidates = candidates_collection.count_documents({})
    
    return render_template('admin_dashboard.html')
# , candidates=candidates,
                        #    total_validated_candidates=total_validated_candidates)

@app.route('/admin_add_candidate', methods=['GET', 'POST'])

def add_candidate():
    # Only allow admins to add candidates
    if session.get('user_role') != 'admin':
        flash("Access denied!", "danger")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        candidate_name = request.form['candidate_name']
        candidates_collection.insert_one({'name': candidate_name, 'votes': 0})
        flash("Candidate added successfully.", "success")
        return redirect(url_for('admin_dashboard'))
    
    return render_template('add_candidate.html')

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session:
        flash("You need to log in first.", "warning")
    # Ensure only users can access this route
    # if session.get('user_role') != 'user':
    #     flash("Access denied!", "danger")
    #     return redirect(url_for('login'))
    
    # Retrieve the list of candidates for voting
    candidates = mongo.db.users.find()
    return render_template('user_dashboard.html')
# , candidates=candidates)

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    # Ensure only users can vote
    # if session.get('user_role') != 'user':
    #     flash("Access denied!", "danger")
    #     return redirect(url_for('login'))
    
    # Get candidate ID and update the vote count
    # candidate_id = request.form['candidate_id']
    # result = candidates_collection.update_one({'_id': ObjectId(candidate_id)}, {'$inc': {'votes': 1}})
    
    # if result.modified_count:
    #     flash("Your vote has been recorded!", "success")
    #     return redirect(url_for('vote_confirmation'))
    # else:
    #     flash("Failed to record vote. Please try again.", "danger")
    
    return render_template('vote.html')

@app.route('/vote_confirmation')
def vote_confirmation():
    return render_template('vote_confirmation.html')

@app.route('/real_time_voting')
def real_time_voting():
    # Display real-time voting updates
    candidates = list(candidates_collection.find())
    return render_template('real_time_voting.html', candidates=candidates)

# Endpoint to fetch real-time vote counts (e.g., using AJAX)
@app.route('/voting_results')
def voting_results():
    # Send the real-time vote counts as JSON data
    candidates = list(candidates_collection.find())
    return jsonify([{'name': candidate['name'], 'votes': candidate['votes']} for candidate in candidates])

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('main_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
