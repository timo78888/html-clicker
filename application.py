# implement cookie clicker but worse

from flask import Flask, render_template, request, session, redirect
from flask_session import Session
from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

# random configuration things
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
db = SQL("sqlite:///click.db")

# casually stolen from helpers.py from CS50 finance
def login_required(f):
    """
    Decorate routes to require login.
    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    # clear session
    session.clear()

    if request.method == "GET":
        return render_template("login.html")
    else:
        username = request.form.get('username')
        password = request.form.get("password")
        check = db.execute("SELECT * from users where username=:username", username=username)
        if len(check) != 1 or not check_password_hash(check[0]['pwdhash'], password):
            return render_template("error.html", message='Invalid username/password!')

        session['user_id'] = check[0]['id']
        return redirect("/page")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        pwdhash = generate_password_hash(request.form.get("password"))
        repeats = db.execute("SELECT username from users where username=:username", username=username)
        if repeats == []:
            db.execute("INSERT INTO users (username, pwdhash) VALUES (:username, :pwdhash)", username=username, pwdhash=pwdhash)
            return render_template("reg_success.html")
        else:
            return render_template("error.html", message='Username taken :/')

@app.route("/page")
@login_required
def game():
    points = db.execute("SELECT points FROM users WHERE id = :user_id", user_id=session['user_id'])[0]['points']
    return render_template("app.html", clicks=points)

@app.route("/logout", methods=['GET', 'POST'])
def logout():
    if request.method == "POST":
        new_clicks = int(request.form.get("testing"))
        old_clicks = db.execute("SELECT points FROM users WHERE id = :user_id", user_id=session['user_id'])[0]['points']
        clicks = old_clicks + new_clicks
        db.execute("UPDATE users SET points=:clicks WHERE id=:user_id", clicks=clicks, user_id=session['user_id'])
        session.clear()
        return redirect("/")
    else:
        session.clear()
        return redirect("/")
