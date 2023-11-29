import os
from dotenv import load_dotenv
from uuid import uuid4

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from flask import Flask, jsonify, request, redirect, send_from_directory, send_file, url_for
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_cors import CORS


from flask_jwt_extended import current_user
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import unset_jwt_cookies

from database import User
from database import Data
from database import SAW
from database import AHP
from database import SAWCriteria
from database import SAWCrisp
from database import AHPCriteria
from database import AHPCrisp
from database import AHPCriteriaImportance
from database import AHPCrispImportance
from database import SAWResultFile
from database import AHPResultFile
from database import TokenBlocklist
from database import db

from method.saw import Criteria as SawCriteria
from method.saw import Crisp as SawCrisp
from method.saw import generate_saw_result

from method.ahp import AHP_Criteria
from method.ahp import input_importance
from method.ahp import calculate_priority
from method.ahp import AHP_Crisp
from method.ahp import generate_crisp_string
from method.ahp import generate_crisp_number
from method.ahp import generate_ahp_result

from error_handler import RaiseError

load_dotenv()

""" APP CONFIGURATION """
app = Flask(__name__)
CORS(app, supports_credentials=True)

UPLOAD_FOLDER = 'uploads'
RESULT_FOLDER = 'result'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000 # 16MB

# Configure Bcrypt
bcrypt = Bcrypt(app)

""" FILE UPLOAD CONFIG """
ALLOWED_EXTENSIONS = {'csv', 'xls'}
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

""" 
CONFIGURE JWT TOKEN 
"""
# Setup the Flask-JWT-Extended extension
ACCESS_EXPIRES = timedelta(hours=3)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_SECRET_KEY"] = os.getenv("SECRET_KEY_JWT")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_COOKIE_CSRF_PROTECT"] = True
jwt = JWTManager(app)

# Callback function to check if a JWT exists in the database blocklist
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()

    return token is not None

# Using an `after_request` callback, we refresh any token that is within 30
# minutes of expiring. Change the timedeltas to match the needs of your application.
@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original response
        return response

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

"""
INIT DATABASE USING SQLALCHEMY
"""
# configure the SQL database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_ECHO'] = False

# Init Database for the App
db.init_app(app)

with app.app_context():
    db.create_all()


""" 
UTILITIES FUNCTIONS
"""
def make_unique(string):
    ident = uuid4().__str__()
    return f"{ident}--{string}"

@app.errorhandler(RaiseError)
def raise_error(e):
    return jsonify(e.to_dict()), e.status_code



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
@app.get('/api/users')
def user_list():
    users = User.query.all()
    if len(users) == 0:
        return jsonify(msg='No Users'), 200
    users_json = []
    for u in users:
        users_json.append(u.to_dict())
    return jsonify(users_json), 200

# USER CREATE
# Parameter: username, password, email
@app.post('/api/user/create')
def user_create():
    check_user = User.query.filter_by(username=request.form['username']).one_or_none()
    if check_user is not None:
        raise RaiseError("Username already exists", 400)
    user = User(
        username=request.form["username"],
        password=bcrypt.generate_password_hash(request.form["password"]).decode('utf-8'),
        name=request.form["name"],
        email=request.form["email"],
    )
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict()), 200

# USER READ
@app.get('/api/user/details')
@jwt_required()
def user_detail():
    user = User.query.filter_by(id=current_user.id).one()
    return jsonify(user.to_dict()), 200

# USER EDIT
# Param: username, email
@app.put('/api/user/update')
@jwt_required()
def user_edit():
    user = User.query.filter_by(id=current_user.id).one_or_none()
    user.username = request.form["username"]
    user.name = request.form["name"]
    user.email = request.form["email"]
    db.session.commit()
    return jsonify(user.to_dict()), 200

# USER CHANGE PASSWORD
# Param: password
@app.put("/api/user/change-password")
@jwt_required()
def user_change_password():
    user = User.query.filter_by(id=current_user.id).one_or_none()
    if user == None:
        raise RaiseError("Something is wrong", 403)
    # Check Password Hash
    if bcrypt.check_password_hash(user.password, request.form["password"]):
        new_password = bcrypt.generate_password_hash(request.form["new_password"]).decode('utf-8')
        user.password = new_password
        db.session.commit()
        return jsonify(msg="Change password success"), 200
    else:
        raise RaiseError("Password is wrong", 403)
    
    
    

# USER DELETE
@app.delete("/api/user/delete")
@jwt_required()
def user_delete():
    user = User.query.filter_by(username=current_user.username).one()
    db.session.delete(user)
    db.session.commit()
    return jsonify(msg="User deleted"), 200

# USER LOGIN
# Param: username, password
@app.post('/api/login')
def login_post():
    user = User.query.filter(User.username == request.form["username"]).first()
    # Username Not Found
    if user == None:
        raise RaiseError("Username or Password is wrong", 403)
    
    # Check Password Hash
    if bcrypt.check_password_hash(user.password, request.form["password"]):
        response = jsonify({"message": "login successful"})
        access_token = create_access_token(identity=user)
        set_access_cookies(response, access_token)
        return response, 200
    else:
        raise RaiseError("Username or Password is wrong", 403)
    
# USER LOGOUT
# Endpoint for revoking the current users access token. Saved the unique
# identifier (jti) for the JWT into our database.
@app.delete('/api/logout')
@jwt_required()
def modify_token():
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    response = jsonify({"message": "Logout Successful"})
    unset_jwt_cookies(response)
    return response, 200


"""


DATA ROUTES

DATA CREATE EDIT, DATA LIST
DATADETAIL CREATE EDIT, DATADETAIL LIST


"""
# DATA CREATE
# Param: Name, File
@app.post('/api/data/create')
@jwt_required()
def data_form():
    # File handler
    file = request.files['file']
    file_path = ''
    filename = ''
    # Check if user upload folder exists
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    if os.path.exists(user_upload_folder) is False:
        os.mkdir(user_upload_folder)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filename = make_unique(filename)
        file_path=os.path.join(user_upload_folder, filename)
    else:
        return jsonify(msg='File type is not acceptable'), 400

    data = Data(
        name=request.form["name"],
        description=request.form["description"],
        file_path=filename,
        user_id=current_user.id
    )
    file.save(file_path) # Save file to designated upload folder
    db.session.add(data)
    db.session.commit()
    return jsonify(data.to_dict()), 200

# DATA LIST READ
@app.get("/api/data")
@jwt_required()
def data_list():
    data = Data.query.filter_by(user_id=current_user.id).all()
    if len(data) == 0:
        return jsonify(msg='Data is Empty'), 200
    data_json = []
    for d in data:
        data_json.append(d.to_dict())
    return jsonify(data_json), 200

# DATA READ
@app.get("/api/data/<data_id>")
@jwt_required()
def data_read(data_id):
    data = Data.query.filter_by(id=data_id, user_id=current_user.id).one_or_none()
    if data is None:
        raise RaiseError("Data is not Found", 404)
    return jsonify(data.to_dict()), 200

@app.get("/api/data/<data_id>/file")
@jwt_required()
def data_file_serve(data_id):
    data = Data.query.filter_by(id=data_id, user_id=current_user.id).one_or_none()
    if data is None:
        raise RaiseError("Data is not Found", 404)
    file_path = os.path.join(current_user.username, data.file_path).replace('\\', '/')
    return send_from_directory(app.config["UPLOAD_FOLDER"], file_path, as_attachment=True)

# DATA UPDATE
# Param: name, file_path
@app.put("/api/data/<data_id>/update")
@jwt_required()
def data_update(data_id):
    data = db.get_or_404(Data, data_id)
    if data.user_id != current_user.id:
        raise RaiseError("Forbidden Resource", 403)
    
    data = Data.query.filter_by(id=data_id).one_or_404()
    # Update name
    data.name = request.form['name']
    # Update filepath
    file = request.files['file']
    file_path=''
    filename = ''
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filename = make_unique(filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username, filename)
    else:
        return jsonify(msg='File type is not acceptable'), 400
    
    data.file_path = filename
    file.save(file_path)
    db.session.commit()

    return jsonify(data.to_dict()), 200

# DATA DELETE
@app.delete("/api/data/<data_id>/delete")
@jwt_required()
def data_delete(data_id):
    data = Data.query.filter_by(id=data_id, user_id=current_user.id).one_or_none()
    if data is None:
        raise RaiseError("Data is not Found", 404)
    db.session.delete(data)
    db.session.commit()
    return jsonify(msg="Data deleted"), 200




""" 


SAW METHOD ROUTES

SAW: CREATE, READ, UPDATE, DELETE
SAW CRITERIA: CREATE, READ, UPDATE
SAW CRISP: CREATE, READ, UPDATE
SAW METHOD RUN


"""
# SAW Create
# Param: Name, Description, Data ID (data_id)
@app.post('/api/saw/create')
@jwt_required()
def saw_create():
    name = request.form['name']
    description = request.form['description']
    data_id = request.form['data_id']

    # Check if user allowed to use the data
    data = Data.query.filter_by(id=data_id).one_or_404()
    if data.user_id != current_user.id:
        return RaiseError('Forbidden Resources', 400)
    
    saw = SAW(
        name=name,
        description=description,
        data_id=data_id
    )
    db.session.add(saw)
    db.session.commit()
    return jsonify(saw.to_dict()), 200

# SAW List Read
@app.get('/api/saw')
@jwt_required()
def saw_list():
    saw = SAW.query.join(Data).filter_by(user_id = current_user.id).order_by(SAW.id).all()
    if len(saw) == 0:
        return jsonify(msg='SAW Empty'), 200
    saw = [s.to_dict() for s in saw]
    return jsonify(saw), 200

# SAW Read
@app.get('/api/saw/<saw_id>')
@jwt_required()
def saw_get(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    return jsonify(saw.to_dict()), 200

# SAW File Read
@app.get('/api/saw/<saw_id>/file/<file_id>')
@jwt_required()
def saw_download_file(saw_id, file_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    saw_file = SAWResultFile.query.filter_by(id=file_id).one_or_none()
    if saw_file is None or saw_file.saw.data.user_id != current_user.id:
        raise RaiseError("SAW File is not Found", 400)
    file_path = os.path.join(current_user.username, "saw", saw_file.file_name).replace('\\', '/')
    return send_from_directory(RESULT_FOLDER, file_path)

# SAW File Delete
@app.delete('/api/saw/<saw_id>/file/<file_id>/delete')
@jwt_required()
def saw_delete_file(saw_id, file_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    saw_file = SAWResultFile.query.filter_by(id=file_id).one_or_none()
    if saw_file is None or saw_file.saw.data.user_id != current_user.id:
        raise RaiseError("SAW File is not Found", 400)
    db.session.delete(saw_file)
    db.session.commit()
    return jsonify(message='File Delete Success'), 200

# SAW Update
@app.put('/api/saw/<saw_id>/update')
@jwt_required()
def saw_update(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw.data.user_id != current_user.id:
        raise RaiseError("Data is not Found", 404)
    
    name = request.form['name']
    description = request.form['description']
    data_id = request.form['data_id']
    saw.name = name
    saw.description = description
    saw.data_id = data_id
    db.session.commit()

    return jsonify(saw.to_dict()), 200

# SAW Delete
@app.delete('/api/saw/<saw_id>/delete')
@jwt_required()
def saw_delete(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    db.session.delete(saw)
    db.session.commit()
    return jsonify(msg='SAW Delete Success'), 200

# SAW CRITERIA Create
# Param: List of SAWCriteria in JSON
@app.post('/api/saw/<saw_id>/criterias/create')
@jwt_required()
def saw_criteria_create(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    if len(saw.saw_criteria) != 0:
        raise RaiseError("SAW already has criterias, update it instead!", 400)

    req = request.json
    for index in range(len(req['name'])):
        criteria = SAWCriteria(
            name=req['name'][index],
            atribute=req['atribute'][index],
            weight=req['weight'][index],
            crisp_type=req['crisp_type'][index],
            saw_id=saw_id
        )    
        db.session.add(criteria)
        db.session.commit()
    saw.update_timestamp()
    db.session.commit()
    saw_criterias = SAWCriteria.query.filter_by(saw_id=saw_id).order_by(SAWCriteria.id).all()
    saw_criterias = [sc.to_dict() for sc in saw_criterias]
    return jsonify(saw_criterias), 200

# SAW Criteria Read
@app.get('/api/saw/<saw_id>/criterias')
@jwt_required()
def saw_criterias_get(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    saw_criteria = saw.saw_criteria
    saw_criteria = [s.to_dict() for s in saw_criteria]
    return jsonify(saw_criteria), 200

# SAW Criteria Update
@app.put('/api/saw/<saw_id>/criterias/update')
@jwt_required()
def saw_criterias_update(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    saw_criteria = saw.saw_criteria
    if len(saw_criteria) == 0:
        raise RaiseError("SAW Criteria is Empty, create it first", 400)
    
    req = request.json
    for index in range(len(saw_criteria)):
        saw_criteria[index].name=req['name'][index]
        saw_criteria[index].atribute=req['atribute'][index]
        saw_criteria[index].weight=req['weight'][index]
        saw_criteria[index].crisp_type=req['crisp_type'][index]
    saw.update_timestamp()
    db.session.commit()

    criteria = SAWCriteria.query.filter_by(saw_id=saw_id).order_by(SAWCriteria.id).all()
    criteria = [c.to_dict() for c in criteria]
    return jsonify(criteria), 200

# SAW Criteria Delete
# You can only delete all criteria
@app.delete('/api/saw/<saw_id>/criterias/delete')
@jwt_required()
def saw_criteria_delete(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    
    saw_criteria = saw.saw_criteria
    if len(saw_criteria) == 0:
        raise RaiseError("SAW doesn\'t have criterias yet", 400)
    
    for index in range(len(saw_criteria)):
        db.session.delete(saw_criteria[index])
        db.session.commit()
    
    saw.update_timestamp()
    db.session.commit()
    return jsonify(msg='Criterias Deleted'), 200

# SAW Crisps Create
@app.post('/api/saw/<saw_id>/criterias/crisps/create')
@jwt_required()
def saw_crisps_create(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    saw_criteria = saw.saw_criteria
    if len(saw_criteria) == 0:
        raise RaiseError("SAW Criteria is Empty, create it first!", 400)
    for s in saw_criteria:
        if len(s.saw_crisp) != 0:
            raise RaiseError("SAW Criteria already has crisps. Update it instead!", 400)

    req = request.json
    # Check length of request is correct
    if len(req) != len(saw_criteria):
        raise RaiseError('Different length of Crisps and Criterias', 400)
    for index in range(len(saw_criteria)):
        for c_index in range(len(req[index]['name'])):
            crisp = SAWCrisp(
                name=req[index]['name'][c_index],
                detail=req[index]['detail'][c_index],
                weight=req[index]['weight'][c_index],
                saw_criteria_id=saw_criteria[index].id
            )
            db.session.add(crisp)
            db.session.commit()
    
    saw_crisps = []
    for c in saw_criteria:
        saw_crisps.extend(SAWCrisp.query.filter_by(saw_criteria_id=c.id).all())
    crisps_json = []
    for s in saw_crisps:  
        crisps_json.append(s.to_dict())
    saw.update_timestamp()
    db.session.commit()
    return jsonify(crisps_json), 200

# SAW Crisps Read
@app.get('/api/saw/<saw_id>/criterias/crisps')
@jwt_required()
def saw_crisps_get(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    if saw.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    saw_criteria = SAWCriteria.query.filter_by(saw_id=saw_id).all()
    if len(saw_criteria) == 0:
        return jsonify('Criterias not Found', 404)
    saw_crisps = []
    for c in saw_criteria:
        saw_crisps.extend(SAWCrisp.query.filter_by(saw_criteria_id=c.id).all())
    crisps_json = []
    for s in saw_crisps:  
        crisps_json.append(s.to_dict())
    return jsonify(crisps_json), 200

# SAW Crips Update
@app.put('/api/saw/<saw_id>/criterias/crisps/update')
@jwt_required()
def saw_crisps_update(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    if saw.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    saw_criteria = SAWCriteria.query.filter_by(saw_id=saw_id).all()
    # Check one of the criteria's crisps
    if len(SAWCrisp.query.filter_by(saw_criteria_id=saw_criteria[0].id).all()) == 0:
        return jsonify(msg='SAW Criteria doesn\'t have crisps yet'), 400
    
    req = request.json
    for index in range(len(saw_criteria)):
        saw_crisps = SAWCrisp.query.filter_by(saw_criteria_id=saw_criteria[index].id).all()
        for c_index in range(len(saw_crisps)):
            saw_crisps[c_index].name=req[index]['name'][c_index]
            saw_crisps[c_index].detail=req[index]['detail'][c_index]
            saw_crisps[c_index].weight=req[index]['weight'][c_index]
        db.session.commit()
    saw.update_timestamp()
    db.session.commit()
    saw_crisps = []
    for c in saw_criteria:
        saw_crisps.extend(SAWCrisp.query.filter_by(saw_criteria_id=c.id).all())
    crisps_json = []
    for s in saw_crisps:  
        crisps_json.append(s.to_dict())
    return jsonify(crisps_json), 200

# SAW Crisp Delete
@app.delete('/api/saw/<saw_id>/criterias/crisps/delete')
@jwt_required()
def saw_crips_delete(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    saw_criteria = SAWCriteria.query.filter_by(saw_id=saw_id).all()
    if len(saw_criteria) == 0:
        return jsonify(msg='SAW Criteria Not Found'), 404
    # Check one of the criteria's crisps
    if len(SAWCrisp.query.filter_by(saw_criteria_id=saw_criteria[0].id).all()) == 0:
        return jsonify(msg='SAW Criteria doesn\'t have crisps yet'), 400
    
    for index in range(len(saw_criteria)):
        crisps = SAWCrisp.query.filter_by(saw_criteria_id=saw_criteria[index].id).all()
        for c in crisps:
            db.session.delete(c)
            db.session.commit()
    saw.update_timestamp()
    db.session.commit()
    return jsonify(msg='Crisps Deleted'), 200

# SAW Crisp (Individual) Create
@app.post('/api/saw/<saw_id>/criterias/<criteria_id>/crisps/create')
@jwt_required()
def saw_crisp_create(saw_id, criteria_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    saw_criteria = SAWCriteria.query.filter_by(id=criteria_id, saw_id=saw_id).one_or_none()
    if saw_criteria is None:
        raise RaiseError("SAW Criteria is not Found", 404)
    if len(saw_criteria.saw_crisp) != 0:
        raise RaiseError("SAW Criteria already has crisps, update it instead!", 400)
    
    req = request.json
    for index in range(len(req['name'])):
        crisp = SAWCrisp(
            name=req['name'][index],
            detail=req['detail'][index],
            weight=req['weight'][index],
            saw_criteria_id=saw_criteria.id
        )
        db.session.add(crisp)
        db.session.commit()
    saw.update_timestamp()
    db.session.commit()
    saw_crisps = SAWCrisp.query.filter_by(saw_criteria_id=saw_criteria.id).order_by(SAWCrisp.id).all()
    saw_crisps = [s.to_dict() for s in saw_crisps]
    return jsonify(saw_crisps), 200

# SAW Crisp (Individual) Read
@app.get('/api/saw/<saw_id>/criterias/<criteria_id>/crisps')
@jwt_required()
def saw_crisp_read(saw_id, criteria_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    saw_criteria = SAWCriteria.query.filter_by(id=criteria_id, saw_id=saw_id).one_or_none()
    if saw_criteria is None:
        raise RaiseError("SAW Criteria is not Found", 404)
    saw_crisp = SAWCrisp.query.filter_by(saw_criteria_id=criteria_id).order_by(SAWCrisp.id).all()
    saw_crisp = [s.to_dict() for s in saw_crisp]
    return jsonify(saw_crisp), 200

# SAW Crisp (Individual) Update
@app.put('/api/saw/<saw_id>/criterias/<criteria_id>/crisps/update')
@jwt_required()
def saw_crisp_update(saw_id, criteria_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    saw_criteria = SAWCriteria.query.filter_by(id=criteria_id, saw_id=saw_id).one_or_none()
    if saw_criteria is None:
        raise RaiseError("SAW Criteria is not Found", 404)
    saw_crisps = SAWCrisp.query.filter_by(saw_criteria_id=criteria_id).order_by(SAWCrisp.id).all()
    if len(saw_crisps) == 0:
        raise RaiseError("SAW Criterria doesn't have crisps yet, create it instead!", 400)
    
    req = request.json
    for index in range(len(saw_crisps)):
        saw_crisps[index].name = req['name'][index]
        saw_crisps[index].detail = req['detail'][index]
        saw_crisps[index].weight = req['weight'][index]
    saw.update_timestamp()
    db.session.commit()
    saw_crisps = SAWCrisp.query.filter_by(saw_criteria_id=criteria_id).order_by(SAWCrisp.id).all()
    saw_crisps = [s.to_dict() for s in saw_crisps]
    return jsonify(saw_crisps), 200

# SAW Crisp (Individual) Delete
@app.delete('/api/saw/<saw_id>/criterias/<criteria_id>/crisps/delete')
@jwt_required()
def saw_crisp_delete(saw_id, criteria_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    saw_criteria = SAWCriteria.query.filter_by(id=criteria_id, saw_id=saw_id).one_or_none()
    if saw_criteria is None:
        raise RaiseError("SAW Criteria is not Found", 404)
    saw_crisps = saw_criteria.saw_crisp
    if len(saw_crisps) == 0:
        raise RaiseError("SAW Criterria doesn't have crisps yet, create it first!", 400)
    
    for index in range(len(saw_crisps)):
        db.session.delete(saw_crisps[index])
    saw.update_timestamp()
    db.session.commit()
    return jsonify(message="SAW Crisps Deleted"), 200

# SAW METHOD
@app.get('/api/saw/<saw_id>/method/create')
@jwt_required()
def saw_method(saw_id):
    """ 
    Check SAW Criterias and Crisps availabilty
    """
    saw = SAW.query.filter_by(id=saw_id).one_or_none()
    if saw is None or saw.data.user_id != current_user.id:
        raise RaiseError("SAW is not Found", 404)
    saw_criteria = SAWCriteria.query.filter_by(saw_id=saw_id).order_by(SAWCriteria.id).all()
    if len(saw_criteria) == 0:
        raise RaiseError("SAW Criteria is not Found", 404)
    # Check criteria crisp's
    for criteria in saw_criteria:
        if len(SAWCrisp.query.filter_by(saw_criteria_id=criteria.id).all()) == 0:
            return jsonify(message="SAW Criteria doesn't have crisps yet", criteria_id=criteria.id), 404
    
    """ 
    Input init for SAW Method
    """
    # Start of criterias init
    criterias = []
    for criteria in saw_criteria:
        crisps = []
        crisps_query = SAWCrisp.query.filter_by(saw_criteria_id=criteria.id).all()
        for crisp in crisps_query:
            name = crisp.name
            weight = crisp.weight
            detail = []
            if criteria.crisp_type == 0:
                d = crisp.detail.split(",")
                detail.append(int(d[0]))
                x = 1
                comparator = []
                while x != len(d):
                    comparator.append(int(d[x]))
                    x += 1
                detail.append(comparator)
            else:
                detail.append(crisp.detail)
            c = SawCrisp(detail=detail, weight=weight)
            crisps.append(c)
        sc = SawCriteria(
            name=criteria.name, 
            weight=criteria.weight, 
            atribute=criteria.atribute,
            crisp_type=criteria.crisp_type,
            crisps=crisps
            )
        criterias.append(sc)
    # End of Criterias init

    data = os.path.join(app.config["UPLOAD_FOLDER"], current_user.username, saw.data.file_path)
    # for c in criterias:
    #     print(c)
    result = generate_saw_result(data_file=data, criterias=criterias)
    """ 
    # Save SAW Result as File
    # """
    # # Check if folder exists
    user_saw_result_folder = os.path.join(RESULT_FOLDER, current_user.username)
    if os.path.exists(user_saw_result_folder) is False:
        os.mkdir(user_saw_result_folder)
    user_saw_result_folder = os.path.join(user_saw_result_folder, 'saw')
    if os.path.exists(user_saw_result_folder) is False:
        os.mkdir(user_saw_result_folder)
    file_name = '{}_{}_SAW.csv'.format(saw.name, datetime.now().strftime('%Y-%m-%d_%H\'%M\'%S'))
    file_path = os.path.join(user_saw_result_folder, file_name)
    result.to_csv(file_path)
     # Save file name to database
    saw_file = SAWResultFile(
        file_name=file_name,
        saw_id=saw_id
    )
    db.session.add(saw_file)
    saw.update_timestamp()
    db.session.commit()
    return jsonify(saw.to_dict()), 200




""" 

AHP METHOD ROUTES

AHP: CREATE, READ, UPDATE, DELETE
AHP CRITERIA: CREATE, READ, UPDATE
AHP CRISP: CREATE, READ, UPDATE
AHP CRITERIA IMPORTANCE: CREATE, READ, UPDATE
AHP CRISP IMPORTANCE: CREATE, READ, UPDATE


"""
# AHP Create
# Param: Name, Description, Data ID (data_id)
@app.post('/api/ahp/create')
@jwt_required()
def ahp_create():
    name = request.form['name']
    description = request.form['description']
    data_id = request.form['data_id']

    # Check if user allowed to use the data
    data = Data.query.filter_by(id=data_id).one_or_none()
    if data is None or data.user_id != current_user.id:
        raise RaiseError('Data is not Found', 404)
    
    ahp = AHP(
        name=name,
        description=description,
        data_id=data_id
    )
    db.session.add(ahp)
    db.session.commit()
    return jsonify(ahp.to_dict()), 200

# AHP List Read
@app.get('/api/ahp')
@jwt_required()
def ahp_list():
    ahp = AHP.query.join(Data).filter_by(user_id = current_user.id).order_by(AHP.id).all()
    if len(ahp) == 0:
        return jsonify(message="AHP Empty"), 200
    ahp_json = []
    for a in ahp:
        ahp_json.append(a.to_dict())
    return jsonify(ahp_json), 200

# AHP Read
@app.get('/api/ahp/<ahp_id>')
@jwt_required()
def ahp_get(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None or ahp.data.user_id != current_user.id:
        raise RaiseError('AHP is not Found', 404)
    return jsonify(ahp.to_dict()), 200

# AHP File Read
@app.get('/api/ahp/<ahp_id>/file/<file_id>')
@jwt_required()
def ahp_download_file(ahp_id, file_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None or ahp.data.user_id != current_user.id:
        raise RaiseError("AHP is not Found", 404)
    ahp_file = AHPResultFile.query.filter_by(id=file_id).one_or_none()
    if ahp_file is None or ahp_file.ahp.data.user_id != current_user.id:
        raise RaiseError("AHP File is not Found", 404)
    file_path = os.path.join(current_user.username, "ahp", ahp_file.file_name).replace('\\', '/')
    return send_from_directory(RESULT_FOLDER, file_path)

# AHP File Delete
@app.delete('/api/ahp/<ahp_id>/file/<file_id>')
@jwt_required()
def ahp_delete_file(ahp_id, file_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None or ahp.data.user_id != current_user.id:
        raise RaiseError("AHP is not Found", 404)
    ahp_file = AHPResultFile.query.filter_by(id=file_id).one_or_none()
    if ahp_file is None or ahp_file.ahp.data.user_id != current_user.id:
        raise RaiseError("AHP File is not Found", 404)
    db.session.delete(ahp_file)
    db.session.commit
    return jsonify(message="File Delete Success"), 200

# AHP Update
@app.put('/api/ahp/<ahp_id>/update')
@jwt_required()
def ahp_update(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None or ahp.data.user_id != current_user.id:
        return RaiseError('AHP is not Found', 404)
    
    name = request.form['name']
    description = request.form['description']
    data_id = request.form['data_id']
    ahp.name = name
    ahp.description = description
    ahp.data_id = data_id
    db.session.commit()

    return jsonify(ahp.to_dict()), 200

# AHP Delete
@app.delete('/api/ahp/<ahp_id>/delete')
@jwt_required()
def ahp_delete(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None or ahp.data.user_id != current_user.id:
        raise RaiseError('AHP is not Found', 404)
    db.session.delete(ahp)
    db.session.commit()
    return jsonify(message='AHP Delete Success'), 200

# AHP Criterias Create
@app.post('/api/ahp/<ahp_id>/criterias/create')
@jwt_required()
def ahp_criteria_create(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None or ahp.data.user_id != current_user.id:
        raise RaiseError("AHP is not Found", 404)
    if len(AHPCriteria.query.filter_by(ahp_id=ahp_id).all()) != 0:
        raise RaiseError('AHP already has criterias! Update criterias instead', 400)

    req = request.json
    for index in range(len(req['name'])):
        criteria = AHPCriteria(
            name=req['name'][index],
            crisp_type=req['crisp_type'][index],
            ahp_id=ahp_id
        )    
        db.session.add(criteria)
        db.session.commit()
    ahp.update_timestamp()
    db.session.commit()
    ahp = AHPCriteria.query.filter_by(ahp_id=ahp_id).all()
    ahp_json = []
    for a in ahp:
        ahp_json.append(a.to_dict())
    return jsonify(ahp_json), 200

# AHP Criterias Read
@app.get('/api/ahp/<ahp_id>/criterias')
@jwt_required()
def ahp_criterias_get(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_404()
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    ahp_criteria = AHPCriteria.query.filter_by(ahp_id=ahp_id).all()
    if len(ahp_criteria) == 0:
        return jsonify('Criterias not Found', 404)
    ahp_json = []
    for a in ahp_criteria:  
        ahp_json.append(a.to_dict())
    return jsonify(ahp_json), 200

# AHP Criterias Update
# If updated, the CRISPS will be DELETED -- not implemented yet
@app.put('/api/ahp/<ahp_id>/criterias/update')
@jwt_required()
def ahp_criterias_update(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_404()
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    
    ahp_criterias = AHPCriteria.query.filter_by(ahp_id=ahp_id).all()
    if len(ahp_criterias) == 0:
        return jsonify(msg='AHP doesn\'t have criterias yet'), 400

    req = request.json
    for index in range(len(ahp_criterias)):
        ahp_criterias[index].name=req['name'][index]
        ahp_criterias[index].crisp_type=req['crisp_type'][index]
    ahp.update_timestamp()
    db.session.commit()

    ahp = AHPCriteria.query.filter_by(ahp_id=ahp_id).all()
    ahp_json = []
    for a in ahp:
        ahp_json.append(a.to_dict())
    return jsonify(ahp_json), 200

# AHP Criterias Delete
# You can only delete all criteria
@app.delete('/api/ahp/<ahp_id>/criterias/delete')
@jwt_required()
def ahp_criteria_delete(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_404()
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    
    ahp_criterias = AHPCriteria.query.filter_by(ahp_id=ahp_id).all()
    if len(ahp_criterias) == 0:
        return jsonify(msg='AHP doesn\'t have criterias yet'), 400
    
    for index in range(len(ahp_criterias)):
        db.session.delete(ahp_criterias[index])
        db.session.commit()
    ahp.update_timestamp()
    db.session.commit()
    return jsonify(msg='Criterias Deleted'), 200

# AHP Criteria Importance Create
# Param: JSON (float number should be sent as string)
@app.post('/api/ahp/<ahp_id>/criterias/importance/create')
@jwt_required()
def ahp_criteria_importance_create(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_404()
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    
    ahp_criterias = AHPCriteria.query.filter_by(ahp_id=ahp_id).order_by(AHPCriteria.id).all()
    if len(ahp_criterias) == 0:
        return jsonify(msg='AHP doesn\'t have criterias yet'), 400
    
    # Check Consistency Ratio
    # Get all criterias list name
    criterias_list = []
    for c in ahp_criterias:
        criterias_list.append(c.name)
    # AHP Criterias
    criterias = []
    for c in ahp_criterias:
        crit = AHP_Criteria(name=c.name, crisp_type=c.crisp_type, criteria_list=criterias_list)
        criterias.append(crit)
    # Get AHP Criterias Importance
    importance_list = []
    for imp in request.json:
        importance_list.append(eval(imp))
    
    input_importance(criterias=criterias, importance_list=importance_list)
    criterias = calculate_priority(criteria_list=criterias_list, criterias=criterias)
    if criterias['status'] is False:
        return jsonify(CR=criterias['CR']), 412
    criterias = criterias['criterias']

    req = request.json
    inc = 0
    for index in range(len(ahp_criterias)-1):
        for i in range(len(ahp_criterias)-1-index):
            imp = AHPCriteriaImportance(
                importance=float(eval(req[inc]))
            )
            db.session.add(imp)
            db.session.commit()
            ahp_criterias[index].importance.append(imp)
            ahp_criterias[index+1+i].importance.append(imp)
            db.session.commit()
            inc += 1
    ahp.update_timestamp()
    db.session.commit()
    ahp_json = []
    for a in ahp_criterias:
        ahp_json.append(a.to_dict())
    return jsonify(ahp_json), 200

# AHP Criterias Importance Read
@app.get('/api/ahp/<ahp_id>/criterias/importance')
@jwt_required()
def ahp_criterias_importance_get(ahp_id):
    ahp = AHPCriteria.query.filter_by(ahp_id=ahp_id).all()
    ahp_json = []
    for a in ahp:
        ahp_json.append(a.to_dict())
    return jsonify(ahp_json), 200

# AHP Criterias Importance Update 
@app.put('/api/ahp/<ahp_id>/criterias/importance/update')
@jwt_required()
def ahp_criterias_importance_update(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_404()
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    
    ahp_criterias = AHPCriteria.query.filter_by(ahp_id=ahp_id).order_by(AHPCriteria.id).all()
    if len(ahp_criterias) == 0:
        return jsonify(msg='AHP doesn\'t have criterias yet'), 400
    
    # Check Consistency Ratio
    # Get all criterias list name
    criterias_list = []
    for c in ahp_criterias:
        criterias_list.append(c.name)
    # AHP Criterias
    criterias = []
    for c in ahp_criterias:
        crit = AHP_Criteria(name=c.name, crisp_type=c.crisp_type, criteria_list=criterias_list)
        criterias.append(crit)
    # Get AHP Criterias Importance
    importance_list = []
    for imp in request.json:
        importance_list.append(eval(imp))
    
    input_importance(criterias=criterias, importance_list=importance_list)
    criterias = calculate_priority(criteria_list=criterias_list, criterias=criterias)
    if criterias['status'] is False:
        return jsonify(CR=criterias['CR']), 412
    criterias = criterias['criterias']

    req = request.json
    inc = 0
    counter = 0
    for index in range(len(ahp_criterias)-1):
        for i in range(len(ahp_criterias)-1-index):
            imp_list = AHPCriteria.query.filter_by(id=ahp_criterias[index].id).one()
            imp_list.importance[i+inc].importance=float(eval(req[counter]))
            db.session.commit()
            counter += 1
        inc+=1
    ahp.update_timestamp()
    db.session.commit()

    ahp_json = []
    for a in ahp_criterias:
        ahp_json.append(a.to_dict())
    return jsonify(ahp_json), 200

# AHP Criterias Importance Delete
@app.delete('/api/ahp/<ahp_id>/criterias/importance/delete')
@jwt_required()
def ahp_criterias_importance_delete(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None or ahp.data.user_id != current_user.id:
        raise RaiseError('Forbidden Resource', 403)
    
    ahp_criterias = AHPCriteria.query.filter_by(ahp_id=ahp_id).order_by(AHPCriteria.id).all()
    if len(ahp_criterias) == 0:
        raise RaiseError('AHP doesn\'t have criterias yet', 400)
    
    imp = []
    inc = 0
    counter = 0
    for index in range(len(ahp_criterias)-1):
        for i in range(len(ahp_criterias)-1-index):
            imp_list = AHPCriteria.query.filter_by(id=ahp_criterias[index].id).one()
            imp.append(imp_list.importance[i+inc])
            counter += 1
        inc+=1
    
    imp = [db.session.delete(i) for i in imp]
    ahp.update_timestamp()
    db.session.commit()
    
    ahp_json = []
    for a in ahp_criterias:
        ahp_json.append(a.to_dict())
    return jsonify(ahp_json), 200

# AHP Crisps Create
@app.post('/api/ahp/<ahp_id>/criterias/crisps/create')
@jwt_required()
def ahp_crisps_create(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    ahp_criteria = AHPCriteria.query.filter_by(ahp_id=ahp_id).all()
    if len(ahp_criteria) == 0:
        return jsonify(msg='AHP Criterias Not Found'), 404
    # Check one of the criteria's crisps
    if len(AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criteria[0].id).all()) != 0:
        return jsonify(msg='AHP Criteria already has crisps! Update crisps instead'), 400

    req = request.json
    # Check length of request is correct
    if len(req) != len(ahp_criteria):
        return jsonify(msg='Different length of Crisps and Criterias'), 400
    
    for index in range(len(ahp_criteria)):
        for c_index in range(len(req[index]['name'])):
            crisp = AHPCrisp(
                name=req[index]['name'][c_index],
                detail=req[index]['detail'][c_index],
                ahp_criteria_id=ahp_criteria[index].id
            )
            db.session.add(crisp)
            db.session.commit()
    ahp.update_timestamp()
    db.session.commit()
    ahp_crisps = []
    for c in ahp_criteria:
        ahp_crisps.extend(AHPCrisp.query.filter_by(ahp_criteria_id=c.id).all())
    crisps_json = []
    for s in ahp_crisps:  
        crisps_json.append(s.to_dict())
    return jsonify(crisps_json), 200

# AHP Crisps Read
@app.get('/api/ahp/<ahp_id>/criterias/crisps')
@jwt_required()
def ahp_crisps_get(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    ahp_criteria = AHPCriteria.query.filter_by(ahp_id=ahp_id).order_by(AHPCriteria.id).all()
    if len(ahp_criteria) == 0:
        return jsonify(msg='AHP Criterias Not Found'), 404
    ahp_crisps = []
    for c in ahp_criteria:
        ahp_crisps.extend(AHPCrisp.query.filter_by(ahp_criteria_id=c.id).order_by(AHPCrisp.id).all())
    if len(ahp_crisps) == 0:
        return jsonify(msg="Crisps Empty"), 200
    crisps_json = []
    for s in ahp_crisps:  
        crisps_json.append(s.to_dict())
    return jsonify(crisps_json), 200

# AHP Crisps Update
@app.put('/api/ahp/<ahp_id>/criterias/crisps/update')
@jwt_required()
def ahp_crisps_update(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    ahp_criteria = AHPCriteria.query.filter_by(ahp_id=ahp_id).order_by(AHPCriteria.id).all()
    if len(ahp_criteria) == 0:
        return jsonify(msg='AHP Criterias Not Found'), 404
    # Check one of the criteria's crisps
    if len(AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criteria[0].id).all()) == 0:
        return jsonify(msg='AHP Criteria doesn\'t have crisps'), 400
    
    req = request.json
    # Check length of request is correct
    if len(req) != len(ahp_criteria):
        return jsonify(msg='Different length of Crisps and Criterias'), 400
    
    for index in range(len(ahp_criteria)):
        ahp_crisps = AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criteria[index].id).order_by(AHPCrisp.id).all()
        for c_index in range(len(req[index]['name'])):
            ahp_crisps[c_index].name=req[index]['name'][c_index]
            ahp_crisps[c_index].detail=req[index]['detail'][c_index]
            db.session.commit()
    ahp.update_timestamp()
    db.session.commit()
    ahp_crisps = []
    for c in ahp_criteria:
        ahp_crisps.extend(AHPCrisp.query.filter_by(ahp_criteria_id=c.id).order_by(AHPCrisp.id).all())
    crisps_json = []
    for s in ahp_crisps:  
        crisps_json.append(s.to_dict())
    return jsonify(crisps_json), 200

# AHP Crisps Delete
@app.delete('/api/ahp/<ahp_id>/criterias/crisps/delete')
@jwt_required()
def ahp_crisps_delete(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    ahp_criteria = AHPCriteria.query.filter_by(ahp_id=ahp_id).order_by(AHPCriteria.id).all()
    if len(ahp_criteria) == 0:
        return jsonify(msg='AHP Criterias Not Found'), 404
    # Check one of the criteria's crisps
    if len(AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criteria[0].id).all()) == 0:
        return jsonify(msg='AHP Criteria doesn\'t have crisps'), 400
    
    for index in range(len(ahp_criteria)):
        crisps = AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criteria[index].id).all()
        for c in crisps:
            db.session.delete(c)
            db.session.commit()
    ahp.update_timestamp()
    db.session.commit()
    return jsonify(msg='Crisps Deleted'), 200

# AHP Crisps Importance Create
@app.post('/api/ahp/<ahp_id>/criterias/crisps/importance/create')
@jwt_required()
def ahp_crisps_importance_create(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    ahp_criterias = AHPCriteria.query.filter_by(ahp_id=ahp_id).order_by(AHPCriteria.id).all()
    if len(ahp_criterias) == 0:
        return jsonify(msg='AHP Criterias Not Found'), 404
    # Check one of the criteria's crisps
    if len(AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criterias[0].id).all()) == 0:
        return jsonify(msg='AHP Criteria doesn\'t have crisps yet'), 400
    # Check if crisps already has importance
    ahp_crisps = AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criterias[0].id).all()
    if len(AHPCrispImportance.query.join(AHPCrispImportance.crisp).filter_by(id=ahp_crisps[0].id).all()) != 0:
        return jsonify(msg="AHP Crisps already have importance value! Update it instead"), 400

    req = request.json
    for index in range (len(ahp_criterias)):
        inc = 0
        crisps = AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criterias[index].id).order_by(AHPCrisp.id).all()
        for i in range(len(crisps)-1):
            for j in range(len(crisps)-1-i):
                imp = AHPCrispImportance(
                    importance=float(eval(req[index][inc]))
                )
                db.session.add(imp)
                db.session.commit()
                crisps[i].importance.append(imp)
                crisps[i+1+j].importance.append(imp)
                db.session.commit()
                inc += 1
    ahp.update_timestamp()
    db.session.commit()
    ahp_crisps = []
    for c in ahp_criterias:
        ahp_crisps.extend(AHPCrisp.query.filter_by(ahp_criteria_id=c.id).order_by(AHPCrisp.id).all())
    if len(ahp_crisps) == 0:
        return jsonify(msg="Crisps Empty"), 200
    crisps_json = []
    for s in ahp_crisps:  
        crisps_json.append(s.to_dict())
    return jsonify(crisps_json), 200

# AHP Crisps Importance Read
@app.get('/api/ahp/<ahp_id>/criterias/crisps/importance')
@jwt_required()
def ahp_crisps_importance_get(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    ahp_criterias = AHPCriteria.query.filter_by(ahp_id=ahp_id).order_by(AHPCriteria.id).all()
    if len(ahp_criterias) == 0:
        return jsonify(msg='AHP Criterias Not Found'), 404
    # Check one of the criteria's crisps
    if len(AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criterias[0].id).all()) == 0:
        return jsonify(msg='AHP Criteria doesn\'t have crisps yet'), 400

    ahp_crisps = []
    for c in ahp_criterias:
        ahp_crisps.extend(AHPCrisp.query.filter_by(ahp_criteria_id=c.id).order_by(AHPCrisp.id).all())
    if len(ahp_crisps) == 0:
        return jsonify(msg="Crisps Empty"), 200
    crisps_json = []
    for s in ahp_crisps:  
        crisps_json.append(s.to_dict())
    return jsonify(crisps_json), 200

# AHP Crisps Importance Update
@app.put('/api/ahp/<ahp_id>/criterias/crisps/importance/update')
@jwt_required()
def ahp_crisps_importance_update(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    ahp_criterias = AHPCriteria.query.filter_by(ahp_id=ahp_id).order_by(AHPCriteria.id).all()
    if len(ahp_criterias) == 0:
        return jsonify(msg='AHP Criterias Not Found'), 404
    # Check one of the criteria's crisps
    if len(AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criterias[0].id).all()) == 0:
        return jsonify(msg='AHP Criteria doesn\'t have crisps yet'), 400
    # Check if crisps already has importance
    ahp_crisps = AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criterias[0].id).all()
    if len(AHPCrispImportance.query.join(AHPCrispImportance.crisp).filter_by(id=ahp_crisps[0].id).all()) == 0:
        return jsonify(msg="AHP Crisps is empty!"), 400
    
    req = request.json
    for index in range (len(ahp_criterias)):
        counter = 0
        inc = 0
        crisps = AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criterias[index].id).order_by(AHPCrisp.id).all()
        for i in range(len(crisps)-1):
            for j in range(len(crisps)-1-i):
                imp_list = AHPCrisp.query.filter_by(id=crisps[i].id).one()
                imp_list.importance[j+inc].importance=float(eval(req[index][counter]))
                db.session.commit()
                counter += 1
            inc+=1
    ahp.update_timestamp()
    db.session.commit()
    ahp_crisps = []
    for c in ahp_criterias:
        ahp_crisps.extend(AHPCrisp.query.filter_by(ahp_criteria_id=c.id).order_by(AHPCrisp.id).all())
    if len(ahp_crisps) == 0:
        return jsonify(msg="Crisps Empty"), 200
    crisps_json = []
    for s in ahp_crisps:  
        crisps_json.append(s.to_dict())
    return jsonify(crisps_json), 200

# AHP Crisp (Individual) Create
@app.post('/api/ahp/<ahp_id>/criterias/<criteria_id>/crisps/create')
@jwt_required()
def ahp_crisp_create(ahp_id, criteria_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    ahp_criteria = AHPCriteria.query.filter_by(id=criteria_id, ahp_id=ahp_id).one_or_none()
    if ahp_criteria == None:
        return jsonify(msg='AHP Criteria Not Found'), 404
    if len(ahp_criteria.ahp_crisp) != 0:
        return jsonify(msg="AHP Crisps already been made, updated it instead!"), 400

    req = request.json
    
    for index in range(len(req['name'])):
        crisp = AHPCrisp(
            name=req['name'][index],
            detail=req['detail'][index],
            ahp_criteria_id=ahp_criteria.id
        )
        db.session.add(crisp)
        db.session.commit()
    ahp.update_timestamp()
    db.session.commit()
    ahp_crisps = AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criteria.id).all()
    if len(ahp_crisps) == 0:
        return jsonify(msg='AHP Crisps input failed something is wrong'), 400
    ahp_crisps = [c.to_dict() for c in ahp_crisps]
    return jsonify(ahp_crisps), 200

# AHP Crisp (Individual) Read
@app.get('/api/ahp/<ahp_id>/criterias/<criteria_id>/crisps')
@jwt_required()
def ahp_crisp_read(ahp_id, criteria_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    ahp_criteria = AHPCriteria.query.filter_by(id=criteria_id, ahp_id=ahp_id).one_or_none()
    if ahp_criteria == None:
        return jsonify(msg='AHP Criteria Not Found'), 404
    ahp_crisps = AHPCrisp.query.filter_by(ahp_criteria_id=criteria_id).order_by(AHPCrisp.id).all()
    ahp_crisps = [c.to_dict() for c in ahp_crisps]
    return jsonify(msg="Crisps is Empty" if len(ahp_crisps) == 0 else ahp_crisps), 200

# AHP Crisps (Individual) Update
@app.put('/api/ahp/<ahp_id>/criterias/<criteria_id>/crisps/update')
@jwt_required()
def ahp_crisp_update(ahp_id, criteria_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    ahp_criteria = AHPCriteria.query.filter_by(id=criteria_id, ahp_id=ahp_id).one_or_none()
    if ahp_criteria == None:
        return jsonify(msg='AHP Criteria Not Found'), 404
    if len(ahp_criteria.ahp_crisp) == 0:
        return jsonify(msg="AHP Crisps is Empty, create it first!"), 400

    req = request.json
    ahp_crisps = AHPCrisp.query.filter_by(ahp_criteria_id=criteria_id).order_by(AHPCrisp.id).all()
    for index in range(len(req['name'])):
        ahp_crisps[index].name = req['name'][index]
        ahp_crisps[index].detail = req['detail'][index]
        db.session.commit()
    ahp.update_timestamp()
    db.session.commit()
    ahp_crisps = AHPCrisp.query.filter_by(ahp_criteria_id=criteria_id).order_by(AHPCrisp.id).all()
    ahp_crisps = [c.to_dict() for c in ahp_crisps]
    return jsonify(ahp_crisps), 200

# AHP Crisp (Individual) Delete
@app.delete('/api/ahp/<ahp_id>/criterias/<criteria_id>/crisps/delete')
@jwt_required()
def ahp_crisp_delete(ahp_id, criteria_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    ahp_criteria = AHPCriteria.query.filter_by(id=criteria_id, ahp_id=ahp_id).one_or_none()
    if ahp_criteria == None:
        return jsonify(msg='AHP Criteria Not Found'), 404
    ahp_crisp = ahp_criteria.ahp_crisp
    if len(ahp_crisp) == 0:
        return jsonify(msg="AHP Crisps is Empty, create it first!"), 400
    
    for index in range(len(ahp_crisp)):
        db.session.delete(ahp_crisp[index])
    ahp.update_timestamp()
    db.session.commit()

    return jsonify(msg='AHP Crisp Delete Success'), 200

# AHP Crisp (Individual) Importance Create
@app.post('/api/ahp/<ahp_id>/criterias/<criteria_id>/crisps/importance/create')
@jwt_required()
def ahp_crisp_importance_create(ahp_id, criteria_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    ahp_criteria = AHPCriteria.query.filter_by(id=criteria_id, ahp_id=ahp_id).one_or_none()
    if ahp_criteria == None:
        return jsonify(msg='AHP Criteria Not Found'), 404
    ahp_crisp = ahp_criteria.ahp_crisp
    if len(ahp_crisp) == 0:
        return jsonify(msg="AHP Crisps is Empty, create it first!"), 400
    for crisp in ahp_crisp:
        if len(crisp.importance) != 0:
            return jsonify(msg='AHP Crisp Importance already Exists, update it instead!', crisp_id=crisp.id), 400
    
    ahp_crisps = AHPCrisp.query.filter_by(ahp_criteria_id=criteria_id).order_by(AHPCrisp.id).all()
    crisps_list = []
    importance_number = []
    inc = 0
    for c in ahp_crisps:
        if ahp_criteria.crisp_type == 0:
            crisp = [c.name]
            detail = []
            d = c.detail.split(",")
            detail.append(int(d[0]))
            x = 1
            comparator = []
            while x != len(d):
                comparator.append(int(d[x]))
                x += 1
            detail.append(comparator)
            crisp.append(detail)
            crisps_list.append(crisp)
        else:
            crisps_list.append(c.detail)
    for imp in request.json:
        importance_number.append(eval(imp))
    crisps = []
    if ahp_criteria.crisp_type == 0:
        print(crisps_list)
        crisps = generate_crisp_number(crisp_list=crisps_list, importance_list=importance_number)
        if crisps['status'] is False:
            raise RaiseError(crisps['CR'], 412)
    else:
        crisps = generate_crisp_string(crisp_list=crisps_list, importance_list=importance_number)
        if crisps['status'] is False:
            raise RaiseError(crisps['CR'], 412)

    req = request.json
    inc = 0
    for index in range(len(ahp_crisp)-1):
        for i in range(len(ahp_crisp)-1-index):
            imp = AHPCrispImportance(
                importance=float(eval(req[inc]))
            )
            db.session.add(imp)
            db.session.commit()
            ahp_crisp[index].importance.append(imp)
            ahp_crisp[index+1+i].importance.append(imp)
            db.session.commit()
            inc += 1
    ahp.update_timestamp()
    db.session.commit()
    ahp_crisp = [c.to_dict() for c in ahp_crisp]
    return jsonify(ahp_crisp), 200

# AHP Crisp (Individual) Importance Read
@app.get('/api/ahp/<ahp_id>/criterias/<criteria_id>/crisps/importance')
@jwt_required()
def ahp_crisp_importance_read(ahp_id, criteria_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    ahp_criteria = AHPCriteria.query.filter_by(id=criteria_id, ahp_id=ahp_id).one_or_none()
    if ahp_criteria == None:
        return jsonify(msg='AHP Criteria Not Found'), 404
    ahp_crisp = AHPCrisp.query.filter_by(ahp_criteria_id=criteria_id).order_by(AHPCrisp.id).all()
    if len(ahp_crisp) == 0:
        return jsonify(msg="AHP Crisps is Empty, create it first!"), 400
    importance = []
    counter = 0
    inc = 0
    for index in range(len(ahp_crisp)-1):
        for i in range(len(ahp_crisp)-1-index):
            importance.append(ahp_crisp[index].importance[i+inc].importance)
            db.session.commit()
            counter += 1
        inc+=1
    return jsonify(importances=importance), 200

# AHP Crisp (Individual) Importance Update
@app.put('/api/ahp/<ahp_id>/criterias/<criteria_id>/crisps/importance/update')
@jwt_required()
def ahp_crisp_importance_update(ahp_id, criteria_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    ahp_criteria = AHPCriteria.query.filter_by(id=criteria_id, ahp_id=ahp_id).one_or_none()
    if ahp_criteria == None:
        return jsonify(msg='AHP Criteria Not Found'), 404
    ahp_crisp = AHPCrisp.query.filter_by(ahp_criteria_id=criteria_id).order_by(AHPCrisp.id).all()
    if len(ahp_crisp) == 0:
        return jsonify(msg="AHP Crisps is Empty, create it first!"), 400
    for crisp in ahp_crisp:
        if len(crisp.importance) == 0:
            return jsonify(msg='AHP Crisp Importance is Empty, create it first', crisp_id=crisp.id), 400
    
    ahp_crisps = AHPCrisp.query.filter_by(ahp_criteria_id=criteria_id).order_by(AHPCrisp.id).all()
    crisps_list = []
    importance_number = []
    inc = 0
    for c in ahp_crisps:
        if ahp_criteria.crisp_type == 0:
            crisp = [c.name]
            detail = []
            d = c.detail.split(",")
            detail.append(int(d[0]))
            x = 1
            comparator = []
            while x != len(d):
                comparator.append(int(d[x]))
                x += 1
            detail.append(comparator)
            crisp.append(detail)
            crisps_list.append(crisp)
        else:
            crisps_list.append(c.detail)
    for imp in request.json:
        importance_number.append(eval(imp))
    crisps = []
    if ahp_criteria.crisp_type == 0:
        print(crisps_list)
        crisps = generate_crisp_number(crisp_list=crisps_list, importance_list=importance_number)
        if crisps['status'] is False:
            raise RaiseError(crisps['CR'], 412)
    else:
        crisps = generate_crisp_string(crisp_list=crisps_list, importance_list=importance_number)
        if crisps['status'] is False:
            raise RaiseError(crisps['CR'], 412)

    req = request.json
    counter = 0
    inc = 0
    for index in range(len(ahp_crisp)-1):
        for i in range(len(ahp_crisp)-1-index):
            ahp_crisp[index].importance[i+inc].importance=float(eval(req[counter]))
            db.session.commit()
            counter += 1
        inc+=1
    ahp_crisp = [c.to_dict() for c in ahp_crisp]
    ahp.update_timestamp()
    db.session.commit()
    return jsonify(ahp_crisp), 200

# AHP Crisp (Individual) Importance Delete
@app.delete('/api/ahp/<ahp_id>/criterias/<criteria_id>/crisps/importance/delete')
@jwt_required()
def ahp_crisp_importance_delete(ahp_id, criteria_id):
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    ahp_criteria = AHPCriteria.query.filter_by(id=criteria_id, ahp_id=ahp_id).one_or_none()
    if ahp_criteria == None:
        return jsonify(msg='AHP Criteria Not Found'), 404
    ahp_crisp = ahp_criteria.ahp_crisp
    if len(ahp_crisp) == 0:
        return jsonify(msg="AHP Crisps is Empty, create it first!"), 400
    for crisp in ahp_crisp:
        if len(crisp.importance) == 0:
            return jsonify(msg='AHP Crisp Importance is Empty, create it first', crisp_id=crisp.id), 400
    
    imp = []
    counter = 0
    inc = 0
    for index in range(len(ahp_crisp)-1):
        for i in range(len(ahp_crisp)-1-index):
            imp.append(ahp_crisp[index].importance[i+inc])
            counter += 1
        inc+=1
    imp = [db.session.delete(i) for i in imp]
    ahp.update_timestamp()
    db.session.commit()
    ahp_crisp = [c.to_dict() for c in ahp_crisp]
    return jsonify(ahp_crisp), 200

# AHP METHOD (BIG CHANGE)
@app.get('/api/ahp/<ahp_id>/method/create')
@jwt_required()
def ahp_method_run(ahp_id):
    """Check Availabilty if method can be run or not"""
    ahp = AHP.query.filter_by(id=ahp_id).one_or_none()
    if ahp is None:
        return jsonify(msg='AHP is not found'), 404
    if ahp.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    ahp_criterias = AHPCriteria.query.filter_by(ahp_id=ahp_id).order_by(AHPCriteria.id).all()
    if len(ahp_criterias) == 0:
        return jsonify(msg='AHP Criterias Not Found'), 404
    # Check one of the criteria's crisps
    if len(AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criterias[0].id).all()) == 0:
        return jsonify(msg='AHP Criteria doesn\'t have crisps yet'), 400
    
    """ 
    Init AHP Criterias
    """
    # Get all criterias list name
    criterias_list = []
    for c in ahp_criterias:
        criterias_list.append(c.name)
    # AHP Criterias
    criterias = []
    for c in ahp_criterias:
        crit = AHP_Criteria(name=c.name, crisp_type=c.crisp_type, criteria_list=criterias_list)
        criterias.append(crit)
    # Get AHP Criterias Importance
    importance_list = []
    inc = 0
    for index in range(len(ahp_criterias)-1):
        for i in range(len(ahp_criterias)-1-index):
            imp_list = AHPCriteria.query.filter_by(id=ahp_criterias[index].id).one()
            importance_list.append(imp_list.importance[i+inc].importance)
        inc+=1
    
    input_importance(criterias=criterias, importance_list=importance_list)
    criterias = calculate_priority(criteria_list=criterias_list, criterias=criterias)
    if criterias['status'] is False:
        raise RaiseError(criterias['CR'], 412)
    criterias = criterias['criterias']
    
    for index in range(len(ahp_criterias)):
        ahp_crisps = AHPCrisp.query.filter_by(ahp_criteria_id=ahp_criterias[index].id).order_by(AHPCrisp.id).all()
        crisps_list = []
        importance_number = []
        inc = 0
        for c in ahp_crisps:
            if ahp_criterias[index].crisp_type == 0:
                crisp = [c.name]
                detail = []
                d = c.detail.split(",")
                detail.append(int(d[0]))
                x = 1
                comparator = []
                while x != len(d):
                    comparator.append(int(d[x]))
                    x += 1
                detail.append(comparator)
                crisp.append(detail)
                crisps_list.append(crisp)
            else:
                crisps_list.append(c.detail)
        for i in range(len(ahp_crisps)-1):
            for j in range(len(ahp_crisps)-1-i):
                imp_list = AHPCrisp.query.filter_by(id=ahp_crisps[i].id).one()
                importance_number.append(imp_list.importance[j+inc].importance)
            inc+=1
        crisps = []
        if ahp_criterias[index].crisp_type == 0:
            print(crisps_list)
            crisps = generate_crisp_number(crisp_list=crisps_list, importance_list=importance_number)
            if crisps['status'] is False:
                raise RaiseError(crisps['CR'], 412)
            crisps = crisps['criterias']
        else:
            crisps = generate_crisp_string(crisp_list=crisps_list, importance_list=importance_number)
            if crisps['status'] is False:
                raise RaiseError(crisps['CR'], 412)
            crisps = crisps['criterias']
        criterias[index].update_crisps(crisps)
    
    for c in criterias[0].crisps:
        print(c)
    
    data_file = os.path.join(app.config["UPLOAD_FOLDER"], current_user.username, ahp.data.file_path)
    result = generate_ahp_result(data_file=data_file, criterias_list=criterias)
    """ 
    # Save AHP Result as File
    # """
    # # Check if folder exists
    user_ahp_result_folder = os.path.join(RESULT_FOLDER, current_user.username)
    if os.path.exists(user_ahp_result_folder) is False:
        os.mkdir(user_ahp_result_folder)
    user_ahp_result_folder = os.path.join(user_ahp_result_folder, 'ahp')
    if os.path.exists(user_ahp_result_folder) is False:
        os.mkdir(user_ahp_result_folder)
    file_name = '{}_{}_AHP.csv'.format(ahp.name, datetime.now().strftime('%Y-%m-%d_%H\'%M\'%S'))
    file_path = os.path.join(user_ahp_result_folder, file_name)
    result.to_csv(file_path)
    # Save file name to database
    ahp_file = AHPResultFile(
        file_name=file_name,
        ahp_id=ahp_id
    )
    db.session.add(ahp_file)
    ahp.update_timestamp()
    db.session.commit()
    return jsonify('Success'), 200

@app.delete('/api/saw/<saw_id>/file/<file_id>/delete')
@jwt_required()
def saw_result_delete(saw_id, file_id):
    saw = SAW.query.filter_by(id=saw_id, user_id=current_user.id).one_or_none()
    if saw is None:
        raise RaiseError("SAW is Not Found", 404)
    saw_file = SAWResultFile.filter_by(saw_id=saw_id, id=file_id).one_or_none()
    if saw_file is None:
        raise RaiseError("SAW File is Not Found", 404)
    db.session.delete(saw_file)
    db.session.commit()
    return jsonify(message="SAW File deleted"), 200

@app.delete('/api/ahp/<ahp_id>/file/<file_id>/delete')
@jwt_required()
def ahp_result_delete(ahp_id, file_id):
    ahp = SAW.query.filter_by(id=ahp_id, user_id=current_user.id).one_or_none()
    if ahp is None:
        raise RaiseError("SAW is Not Found", 404)
    ahp_file = SAWResultFile.filter_by(saw_id=ahp_id, id=file_id).one_or_none()
    if ahp_file is None:
        raise RaiseError("SAW File is Not Found", 404)
    db.session.delete(ahp_file)
    db.session.commit()
    return jsonify(message="AHP File deleted"), 200

@app.get('/api/protectedview')
@jwt_required()
def protected_view():
    return jsonify(message="Welcome to protected view")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)