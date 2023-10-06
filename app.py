import os
from dotenv import load_dotenv
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from flask import Flask, jsonify, request, redirect, flash, url_for
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt

from flask_jwt_extended import create_access_token
from flask_jwt_extended import current_user
from flask_jwt_extended import get_jwt
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

from database import User
from database import Data
from database import DataDetail
from database import TokenBlocklist
from database import MultiCriteria
from database import db

from error_handler import RaiseError

load_dotenv()

""" APP CONFIGURATION """
app = Flask(__name__)
UPLOAD_FOLDER = './uploads'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000 # 16MB

# Configure Bcrypt
bcrypt = Bcrypt(app)

@app.errorhandler(RaiseError)
def raise_error(e):
    return jsonify(e.to_dict()), e.status_code

""" FILE UPLOAD CONFIG """
ALLOWED_EXTENSIONS = {'csv', 'xlsx'}
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

""" 
CONFIGURE JWT TOKEN 
"""
# Setup the Flask-JWT-Extended extension
ACCESS_EXPIRES = timedelta(hours=1)
app.config["JWT_SECRET_KEY"] = os.getenv("SECRET_KEY_JWT")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
jwt = JWTManager(app)

# Callback function to check if a JWT exists in the database blocklist
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()

    return token is not None

"""
INIT DATABASE USING SQLALCHEMY
"""
# configure the SQL database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")

# Init Database for the App
db.init_app(app)

with app.app_context():
    db.create_all()

"""
CALLBACK FUNCTION
"""

# Register a callback function that takes whatever object is passed in as the
# identity when creating JWTs and converts it to a JSON serializable format.
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


# Register a callback function that loads a user from your database whenever
# a protected route is accessed. This should return any python object on a
# successful lookup, or None if the lookup failed for any reason (for example
# if the user has been deleted from the database).
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


"""""
ROUTES
"""""
# HOME
@app.route('/')
def home():
    return "Hello world!"


"""
USER ROUTES

CREATE, EDIT, LOGIN, LOGOUT, LIST, READ
"""
# USER LIST
@app.get("/users")
def user_list():
    users = User.query.all()
    users_json = []
    for u in users:
        users_json.append(u.to_dict())
    return jsonify(users_json), 200

# USER CREATE
# Parameter: username, password, email
@app.post("/user/create")
def user_create():
    user = User(
        username=request.form["username"],
        password=bcrypt.generate_password_hash(request.form["password"]).decode('utf-8'),
        email=request.form["email"],
    )
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict()), 200

# USER READ
@app.get("/user/details")
@jwt_required()
def user_detail():
    user = User.query.filter_by(id=current_user.id).one()
    return jsonify(user.to_dict()), 200

# USER EDIT
# Param: username, email
@app.put("/user/update")
@jwt_required()
def user_edit():
    user = User.query.filter_by(id=current_user.id).one()
    user.username = request.form["username"]
    user.email = request.form["email"]
    return redirect('/user/details')

# USER CHANGE PASSWORD
# Param: password
@app.put("/user/change-password")
@jwt_required()
def user_change_password():
    user = User.query.filter_by(id=current_user.id).one()
    new_password = bcrypt.generate_password_hash(request.form["password"]).decode('utf-8')
    user.password = new_password
    db.session.commit()
    return jsonify(msg="Change password success"), 200

# USER DELETE
@app.delete("/user/delete")
@jwt_required()
def user_delete():
    user = User.query.filter_by(username=current_user.username).one()
    db.session.delete(user)
    db.session.commit()
    return jsonify(msg="User deleted"), 200

# USER LOGIN
# Param: username, password
@app.post("/login")
def login_post():
    user = User.query.filter(User.username == request.form["username"]).first()
    # Username Not Found
    if user == None:
        raise RaiseError("Username or Password is wrong", 403)
    
    # Check Password Hash
    if bcrypt.check_password_hash(user.password, request.form["password"]):
        access_token = create_access_token(identity=user)
        return jsonify(access_token=access_token)
    else:
        raise RaiseError("Username or Password is wrong", 403)
    
# USER LOGOUT
# Endpoint for revoking the current users access token. Saved the unique
# identifier (jti) for the JWT into our database.
@app.delete("/logout")
@jwt_required()
def modify_token():
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(msg="JWT Revoked"), 200


"""
DATA ROUTES

DATA CREATE EDIT, DATA LIST
DATADETAIL CREATE EDIT, DATADETAIL LIST
"""
# DATA CREATE
# Param: Name, File
@app.post("/data/create")
@jwt_required()
def data_form():
    # File handler
    file = request.files['file']
    file_path = ''
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username, 'data')
    if(os.path.exists(user_upload_folder) is False):
        os.mkdir(user_upload_folder)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path=os.path.join(user_upload_folder, filename)
    data = Data(
        name=request.form["name"],
        file_path=file_path,
        user_id=current_user.id
    )
    file.save(file_path, filename) # Save file to designated upload folder
    db.session.add(data)
    db.session.commit()
    return jsonify(data.to_dict()), 200

# DATA READ
@app.get("/data")
@jwt_required()
def data_list():
    data = Data.query.filter_by(user_id=current_user.id).all()
    data_json = []
    for d in data:
        data_json.append(d.to_dict())
    return jsonify(data_json), 200

# DATA UPDATE
# Param: name, file_path
@app.get("/data/<data_id>/update")
@jwt_required()
def data_update(data_id):
    data = db.get_or_404(Data, data_id)
    if data.id != current_user.id:
        raise RaiseError("Forbidden Resource", 403)
    data = Data.query.filter_by(id=data_id).one()
    data_json = []
    for d in data:
        data_json.append(d.to_dict())
    return jsonify(data_json)

# DATA DELETE
@app.delete("/data/<data_id>/delete")
@jwt_required
def data_delete(data_id):
    data = db.get_or_404(Data, data_id)
    if data.id != current_user.id:
        raise RaiseError("Forbidden Resource", 403)
    db.session.delete(data)
    db.session.commit()
    return jsonify(msg="Data deleted"), 200

# DATA DETAIL CREATE
# Param: details (JSON)
@app.post("/data/<data_id>/details/create")
@jwt_required()
def data_detail_form(data_id):
    data = db.get_or_404(Data, data_id)
    if data.id != current_user.id:
        raise RaiseError("Forbidden Resource", 403)
    details = request.json
    # Update existing Criteria
    if DataDetail.query.filter_by(data_id=data.id).first() is not None:
        counter = 0
        for data in DataDetail.query.filter_by(data_id=data_id):
            data.criteria = details['details'][counter]['criteria']
            data.type = details['details'][counter]['type']
            counter += 1
        db.session.commit()
    else:
        # Create new Criteria if None
        for d in details['details']:
            detail = DataDetail(
                criteria=d["criteria"],
                type=d["type"],
                data_id=data.id
            )
            db.session.add(detail)
            db.session.commit()
    return redirect('/data/{}/details'.format(data_id))

@app.get('/data/<data_id>/details')
@jwt_required()
def data_detail(data_id):
    data = db.get_or_404(Data, data_id)
    if data.user_id != current_user.id:
        raise RaiseError("Forbidden Resource", 403)
    
    details = DataDetail.query.filter_by(data_id=data_id).all()
    details_dict = []
    for d in details:
        details_dict.append(d.to_dict())
    return jsonify(details_dict)

# MULTI CRITERIA DETAIL
# Param: JSON Object
""" 
{
    "multicriteria": ["tata boga", "tata busana", "kendaraan ringan"]
}
"""
@app.put('/data/<data_id>/detail/<detail_id>/update')
@jwt_required()
def multi_criteria_post(data_id, detail_id):
    data_detail = db.get_or_404(DataDetail, detail_id)
    req = request.json
    multicriteria = req["multicriteria"]
    for mc in multicriteria:
        criteria = MultiCriteria(
            name=mc
        )
        db.session.add(criteria)
        data_detail.mcdetails.append(criteria)
        db.session.commit()
    return redirect('/data/{}/details'.format(data_id))

@app.get("/who_am_i")
@jwt_required()
def who_am_i():
    # We can now access our sqlalchemy User object via `current_user`.
    return jsonify(
        id=current_user.id,
        username=current_user.username,
    )