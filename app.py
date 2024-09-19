from flask import Flask, render_template, request, redirect, url_for, session, flash, app
from werkzeug.security import generate_password_hash,check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from datetime import timedelta


app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres:4b%233uXfCF%242@localhost/VPNCustdb'
db = SQLAlchemy(app)
app.permanent_session_lifetime= timedelta(days=1)


class Data(db.Model):
    __tablename__="mydata"
    id=db.Column(db.Integer,primary_key=True)
    first_name= db.Column(db.String(50))
    last_name= db.Column(db.String(50))
    email=db.Column(db.String(120),unique=True)
    password=db.Column(db.String(128),unique=True)#for hashing the password increase string length

    def __init__(self,first_name,last_name,email,password):
        self.first_name= first_name
        self.last_name= last_name
        self.email=email
        self.password=password

with app.app_context():
    db.create_all()

@app.route("/")
def index():
    message = request.args.get('message')
    message_type = request.args.get('message_type')
    return render_template('index.html', message=message, message_type=message_type)

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/signup", methods=['POST','GET'])
def signup():
    if request.method == 'POST':
        session.permanent= True
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']

        # Generate a hashed version of the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Output the hashed password
        print(hashed_password)

        data = Data(first_name, last_name, email, hashed_password)
        try:
            db.session.add(data)   
            db.session.commit()
            return redirect(url_for('index', message='Registration Successful', message_type='success'))  
        except IntegrityError as e:
            db.session.rollback()
            if 'unique constraint' in str(e):
                flash('Email or phone number already exists.', 'danger')
                return redirect(url_for('index', message='Account already exists', message_type='exists'))
            else:
                flash(f'An error occurred: {e}', 'danger')
                return redirect(url_for('signup', f'An error occurred: {e}', message_type='failure'))
    return render_template("signup.html")


@app.route("/login", methods=['POST'])
def login():
    email = request.form['login_email']
    password = request.form['login_password']
    user = Data.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        session['email'] = user.email
        session['user_name'] = user.first_name  # Store the user's first name
        return render_template("index.Html", message='Login Successful', message_type='success')
        # return redirect(url_for('index'))  
    else:
        return redirect(url_for('index', message='Invalid email or password', message_type='failure'))
     
@app.route("/logout")
def logout():
    session.pop('email', None)
    session.pop('user_name', None)
    return redirect(url_for('index', message='Logged out successfully', message_type='success'))


@app.route("/test")
def test():
    return render_template("test.html")
    
# Automatically updates changes
if __name__ == "__main__":
    app.debug=True
    app.run(debug=True)
