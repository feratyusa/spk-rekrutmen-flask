import os
from flask import Flask
from flask import jsonify
from flask import request
from dotenv import load_dotenv

from database import User
from database import Database as db

load_dotenv()

app = Flask(__name__)

# configure the SQL database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")

# Init Database for the App
db.init_app(app)

with app.app_context():
    db.create_all()

# Routes

# HOME
@app.route('/')
def home():
    return "Hello world!"

# USER LIST
@app.route("/users")
def user_list():
    users = User.query.all()
    users_json = []
    for u in users:
        users_json.append(u.to_dict())
    return jsonify(users_json)

# USER CREATE
@app.post("/users/create")
def user_create():
    user = User(
        username=request.form["username"],
        password=request.form["password"],
        email=request.form["email"],
    )
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict())

# USER GET
@app.get("/user/<int:id>")
def user_detail(id):
    user = db.get_or_404(User, id)
    return jsonify(user.to_dict())