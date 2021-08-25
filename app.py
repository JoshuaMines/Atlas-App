from datetime import datetime
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user,LoginManager, login_required, logout_user, current_user 
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField
from wtforms.fields.core import DateField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from wtforms.fields.html5 import DateField
import matplotlib.pyplot as plt
import numpy as np
from PIL import Image
import base64
import io


app = Flask(__name__)
db = SQLAlchemy(app)
Bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



#workout goals
class goals(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    squatg = db.Column(db.Integer())
    deadliftg = db.Column(db.Integer())
    benchg = db.Column(db.Integer())

class goalsForm(FlaskForm):
    
    squatg = IntegerField('Squat Goal', [Length(min=1, max=3)])
    deadliftg = IntegerField('Deadlift Goal', [Length(min=1, max=3)])
    benchg = IntegerField('Bench Goal', [Length(min=1, max=3)])

    submit =SubmitField("Submit")

#today's lift
class lifts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime)
    squat = db.Column(db.Integer())
    deadlift = db.Column(db.Integer())
    bench = db.Column(db.Integer())

class liftForm(FlaskForm):
    date = DateField('Date', format='%Y-%m-%d')
    squat = IntegerField('Squats', [Length(min=1, max=3)])
    deadlift = IntegerField('Deadlifts', [Length(min=1, max=3)])
    bench = IntegerField('Benchs', [Length(min=1, max=3)])

    submit =SubmitField("Submit")

#current ls
class nutrition(db.Model):
    id 



#login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder":"Username"})

    password = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder":"Password"})

    submit = SubmitField("Register")        

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError(
                "That username already exsists!")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder":"Username"})

    password = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder":"Password"})

    submit = SubmitField("Login")   

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if Bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route ('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = Bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    form = liftForm()

    liftz = lifts(squat=form.squat.data,
                    deadlift=form.deadlift.data,
                    bench=form.bench.data)
    db.session.add(liftz)
    db.session.commit()
    return render_template('dashboard.html', form=form)

@app.route('/personal', methods=['GET', 'POST'])
def personal():
    form = goalsForm()

    goalz = goals(squatg=form.squatg.data,
                        deadliftg=form.deadliftg.data, 
                        benchg=form.benchg.data)
    db.session.add(goalz)
    db.session.commit()
    
@app.route('/dashboard', methods=['POST', 'GET'])
def show_image():
    x = np.linspace(-1, 1, 50)
    y1 = 2*x + 1
    y2 = 2**x + 1
    y3= 3*x + 1

    plt.figure(num = 3, figsize=(8, 5))
    plt.plot(x, y2)
    plt.plot(x, y3,
            color='purple')
    plt.plot(x, y1, 
            color='red',   
            linewidth=1.0,  
            linestyle='--' 
            )

    plt.save('generated_plot.png')
    im = Image.open("generated_plot.png") #Open the generated image
    data = io.BytesIO() 
    im.save(data, "png")
    encoded_img_data = base64.b64encode(data.getvalue())

    return render_template("dashboard.html", img=encoded_img_data.decode('utf-8'))
 
if __name__== '__main__':
    app.run(debug=True, port=4000)