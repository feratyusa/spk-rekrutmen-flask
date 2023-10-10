import os
from dotenv import load_dotenv
from uuid import uuid4

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from flask import Flask, jsonify, request, redirect
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt

from flask_jwt_extended import create_access_token
from flask_jwt_extended import current_user
from flask_jwt_extended import get_jwt
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

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
from database import TokenBlocklist
from database import db

from method.saw import Criteria as SawCriteria
from method.saw import Crisp as SawCrisp

from error_handler import RaiseError

load_dotenv()

""" APP CONFIGURATION """
app = Flask(__name__)
UPLOAD_FOLDER = '.\\uploads'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000 # 16MB

# Configure Bcrypt
bcrypt = Bcrypt(app)

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
@app.get("/users")
def user_list():
    users = User.query.all()
    if len(users) is 0:
        return jsonify(msg='No Users'), 200
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
    # Check if user upload folder exists
    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    if os.path.exists(user_upload_folder) is False:
        os.mkdir(user_upload_folder)
    # Check if user upload data folder exists
    user_upload_data_folder = os.path.join(user_upload_folder, 'data')
    if os.path.exists(user_upload_data_folder) is False:
        os.mkdir(user_upload_data_folder)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path=os.path.join(user_upload_data_folder, make_unique(filename))
    else:
        return jsonify(msg='File type is not acceptable'), 400

    data = Data(
        name=request.form["name"],
        file_path=file_path,
        user_id=current_user.id
    )
    file.save(file_path) # Save file to designated upload folder
    db.session.add(data)
    db.session.commit()
    return jsonify(data.to_dict()), 200

# DATA LIST READ
@app.get("/data")
@jwt_required()
def data_list():
    data = Data.query.filter_by(user_id=current_user.id).all()
    if len(data) is 0:
        return jsonify(msg='Data is Empty'), 200
    data_json = []
    for d in data:
        data_json.append(d.to_dict())
    return jsonify(data_json), 200

# DATA UPDATE
# Param: name, file_path
@app.put("/data/<data_id>/update")
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
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username, 'data', make_unique(filename))
    else:
        return jsonify(msg='File type is not acceptable'), 400
    
    data.file_path = file_path
    file.save(file_path)
    db.session.commit()

    return jsonify(data.to_dict()), 200

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

""" 
SAW METHOD ROUTES
SAW: CREATE, READ, UPDATE, DELETE
SAW CRITERIA: CREATE, READ, UPDATE
SAW CRISP: CREATE, READ, UPDATE
"""
# SAW Create
# Param: Name, Description, Data ID (data_id)
@app.post('/saw/create')
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
@app.get('/saw')
@jwt_required()
def saw_list():
    saw = SAW.query.join(Data).filter_by(user_id = current_user.id).all()
    if len(saw) is 0:
        return jsonify(msg='SAW Empty'), 200
    saw_json = []
    for s in saw:
        saw_json.append(s.to_dict())
    return jsonify(saw_json), 200

# SAW Read
@app.get('/saw/<saw_id>')
@jwt_required()
def saw_get(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    return jsonify(saw.to_dict()), 200

# SAW Update
@app.put('/saw/<saw_id>/update')
@jwt_required()
def saw_update(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    
    name = request.form['name']
    description = request.form['description']
    data_id = request.form['data_id']
    saw.name = name
    saw.description = description
    saw.data_id = data_id
    return jsonify(saw.to_dict()), 200

# SAW Delete
@app.delete('/saw/<saw_id>/delete')
@jwt_required()
def saw_delete(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    if saw.data.user_id != current_user.id:
        return RaiseError('Forbidden Resource', 403)
    db.session.delete(saw)
    db.session.commit()
    return jsonify(msg='SAW Delete Success'), 200

# SAW CRITERIA Create
# Param: List of SAWCriteria in JSON
@app.post('/saw/<saw_id>/criterias/create')
@jwt_required()
def saw_criteria_create(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    if saw.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    if len(SAWCriteria.query.filter_by(saw_id=saw_id).all()) is not 0:
        return jsonify(msg='SAW already has criterias! Update criterias instead'), 400

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
    
    ahp = SAWCriteria.query.filter_by(saw_id=saw_id).all()
    ahp_json = []
    for a in ahp:
        ahp_json.append(a.to_dict())
    return jsonify(ahp_json), 200

# SAW Criteria Read
@app.get('/saw/<saw_id>/criterias')
@jwt_required()
def saw_criterias_get(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    if saw.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    saw_criteria = SAWCriteria.query.filter_by(saw_id=saw_id).all()
    if len(saw_criteria) is 0:
        return jsonify('Criterias not Found', 404)
    saw_json = []
    for s in saw_criteria:  
        saw_json.append(s.to_dict())
    return jsonify(saw_json), 200

# SAW Criteria Update
# If updated, the CRISPS will be DELETED
@app.put('/saw/<saw_id>/criterias/update')
@jwt_required()
def saw_criterias_update(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    if saw.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    
    saw_criteria = SAWCriteria.query.filter_by(saw_id=saw_id).all()
    if len(saw_criteria) is 0:
        return jsonify(msg='SAW doesn\'t have criterias yet'), 400

    req = request.json
    for index in range(len(saw_criteria)):
        saw_criteria[index].name=req['name'][index]
        saw_criteria[index].atribute=req['atribute'][index]
        saw_criteria[index].weight=req['weight'][index]
        saw_criteria[index].crisp_type=req['crisp_type'][index]
    db.session.commit()
    criteria = SAWCriteria.query.filter_by(saw_id=saw_id).all()
    criteria_json = []
    for a in criteria:
        criteria_json.append(a.to_dict())
    return jsonify(criteria_json), 200

# SAW Criteria Delete
# You can only delete all criteria
@app.delete('/saw/<saw_id>/criterias/delete')
@jwt_required()
def saw_criteria_delete(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    if saw.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    
    saw_criteria = SAWCriteria.query.filter_by(saw_id=saw_id).all()
    if len(saw_criteria) is 0:
        return jsonify(msg='SAW doesn\'t have criterias yet'), 400
    
    for index in range(len(saw_criteria)):
        db.session.delete(saw_criteria[index])
        db.session.commit()
    return jsonify(msg='Criterias Deleted'), 200

# SAW Crisps Create
@app.post('/saw/<saw_id>/criterias/crisps/create')
@jwt_required()
def saw_crisps_create(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    if saw.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    saw_criteria = SAWCriteria.query.filter_by(saw_id=saw_id).all()
    if len(saw_criteria) is 0:
        return jsonify(msg='SAW Criteria Not Found'), 404
    # Check one of the criteria's crisps
    if len(SAWCrisp.query.filter_by(saw_criteria_id=saw_criteria[0].id).all()) is not 0:
        return jsonify(msg='SAW Criteria already has crisps! Update crisps instead'), 400

    req = request.json
    # Check length of request is correct
    if len(req) is not len(saw_criteria):
        return jsonify(msg='Different length of Crisps and Criterias'), 400
    
    for index in range(len(saw_criteria)):
        if saw_criteria[index].crisp_type == 2:
            req[index]["name"].append("None")
            req[index]["detail"].append("None")
            req[index]["weight"].append(1)
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
    return jsonify(crisps_json), 200

# SAW Crisps Read
@app.get('/saw/<saw_id>/criterias/crisps')
@jwt_required()
def saw_crisps_get(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    if saw.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    saw_criteria = SAWCriteria.query.filter_by(saw_id=saw_id).all()
    if len(saw_criteria) is 0:
        return jsonify('Criterias not Found', 404)
    saw_crisps = []
    for c in saw_criteria:
        saw_crisps.extend(SAWCrisp.query.filter_by(saw_criteria_id=c.id).all())
    crisps_json = []
    for s in saw_crisps:  
        crisps_json.append(s.to_dict())
    return jsonify(crisps_json), 200

# SAW Crips Update
@app.put('/saw/<saw_id>/criterias/crisps/update')
@jwt_required()
def saw_crisp_update(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    if saw.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    saw_criteria = SAWCriteria.query.filter_by(saw_id=saw_id).all()
    # Check one of the criteria's crisps
    if len(SAWCrisp.query.filter_by(saw_criteria_id=saw_criteria[0].id).all()) is 0:
        return jsonify(msg='SAW Criteria doesn\'t have crisps yet'), 400
    
    req = request.json
    for index in range(len(saw_criteria)):
        if saw_criteria[index].crisp_type == 2:
            req[index]["name"].append("None")
            req[index]["detail"].append("None")
            req[index]["weight"].append(1)
        saw_crisps = SAWCrisp.query.filter_by(saw_criteria_id=saw_criteria[index].id).all()
        for c_index in range(len(saw_crisps)):
            saw_crisps[c_index].name=req[index]['name'][c_index]
            saw_crisps[c_index].detail=req[index]['detail'][c_index]
            saw_crisps[c_index].weight=req[index]['weight'][c_index]
        db.session.commit()
    saw_crisps = []
    for c in saw_criteria:
        saw_crisps.extend(SAWCrisp.query.filter_by(saw_criteria_id=c.id).all())
    crisps_json = []
    for s in saw_crisps:  
        crisps_json.append(s.to_dict())
    return jsonify(crisps_json), 200

# SAW Crisp Delete
@app.delete('/saw/<saw_id>/criterias/crisps/delete')
@jwt_required()
def saw_crips_delete(saw_id):
    saw = SAW.query.filter_by(id=saw_id).one_or_404()
    if saw.data.user_id != current_user.id:
        return jsonify(msg='Forbidden Resource'), 403
    saw_criteria = SAWCriteria.query.filter_by(saw_id=saw_id).all()
    if len(saw_criteria) is 0:
        return jsonify(msg='SAW Criteria Not Found'), 404
    # Check one of the criteria's crisps
    if len(SAWCrisp.query.filter_by(saw_criteria_id=saw_criteria[0].id).all()) is 0:
        return jsonify(msg='SAW Criteria doesn\'t have crisps yet'), 400
    
    for index in range(len(saw_criteria)):
        crisps = SAWCrisp.query.filter_by(saw_criteria_id=saw_criteria[index].id).all()
        for c in crisps:
            db.session.delete(c)
            db.session.commit()
    return jsonify(msg='Crisps Deleted'), 200


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
@app.post('/ahp/create')
@jwt_required()
def ahp_create():
    name = request.form['name']
    description = request.form['description']
    data_id = request.form['data_id']

    # Check if user allowed to use the data
    data = Data.query.filter_by(id=data_id).one()
    if data.user_id != current_user.id:
        return RaiseError('Forbidden Resources', 400)
    
    ahp = AHP(
        name=name,
        description=description,
        data_id=data_id
    )
    db.session.add(ahp)
    db.session.commit()
    return jsonify(ahp.to_dict()), 200

# AHP List Read
@app.get('/ahp')
@jwt_required()
def ahp_list():
    ahp = AHP.query.join(Data).filter_by(user_id = current_user.id).all()
    ahp_json = []
    for a in ahp:
        ahp_json.append(a.to_dict())
    return jsonify(ahp_json), 200

# AHP Read
@app.get('/ahp/<ahp_id>')
@jwt_required()
def ahp_get(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one()
    if ahp.data.user_id != current_user.id:
        return RaiseError('Forbidden Resource', 403)
    return jsonify(ahp.to_dict()), 200

# AHP Update
@app.put('/ahp/<ahp>/update')
@jwt_required()
def ahp_update(ahp_id):
    ahp = SAW.query.filter_by(id=ahp_id).one()
    if ahp.data.user_id != current_user.id:
        return RaiseError('Forbidden Resource', 403)
    
    name = request.form['name']
    description = request.form['description']
    data_id = request.form['data_id']
    ahp.name = name
    ahp.description = description
    ahp.data_id = data_id
    return jsonify(ahp.to_dict()), 200

# AHP Delete
@app.delete('/ahp/<ahp_id>/delete')
@jwt_required()
def ahp_delete(ahp_id):
    ahp = AHP.query.filter_by(id=ahp_id).one()
    if ahp.data.user_id != current_user.id:
        return RaiseError('Forbidden Resource', 403)
    db.session.delete(ahp)
    db.session.commit()
    return jsonify(msg='AHP Delete Success'), 200

@app.get("/who_am_i")
@jwt_required()
def who_am_i():
    # We can now access our sqlalchemy User object via `current_user`.
    return jsonify(
        id=current_user.id,
        username=current_user.username,
    )