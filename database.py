from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.sql import func

# Database Initialization
# Base Model Declaration
class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)
""" 
Number of Models = 9
a. User: User of the application
b. Data: Data details that will be used
c. SAWCriteria: Criteria of the data (SAW Method)
c. SAWCrisp: Crisp / Sub criteria of the data (SAW Method)
d. AHPCriteria: Criteria of the data (AHP Method)
e. AHPCrisp: Crisp / Sub criteria of the data (AHP Method)
f. AHPCriteriaImportance: Importance value of the criteria (AHP Method)
g. AHPCrispImportance: Importance value of the crisp (AHP Method)
"""

# This could be expanded to fit the needs of your application. For example,
# it could track who revoked a JWT, when a token expires, notes for why a
# JWT was revoked, an endpoint to un-revoked a JWT, etc.
# Making jti an index can significantly speed up the search when there are
# tens of thousands of records. Remember this query will happen for every
# (protected) request,
# If your database supports a UUID type, this can be used for the jti column
# as well
class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)

# Models
class User(db.Model, SerializerMixin):
  __tablename__ = "user"

  serialize_only = ('id', 'username', 'password', 'created_at', 'updated_at')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String, unique=True, nullable=False)
  password = db.Column(db.String)
  email = db.Column(db.String)
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  data = db.relationship('Data', backref='user')

  def __repr__(self):
    return f'<User "{self.username}">' 

class Data(db.Model, SerializerMixin):
  __tablename__ = "data"

  serialize_only = ('id', 'name', 'file_path', 'created_at', 'updated_at')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String, nullable=False)
  file_path = db.Column(db.String, nullable=False)
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
  saw = db.relationship('SAW', backref='data')
  ahp = db.relationship('AHP', backref='data')

  def __repr__(self):
    return f'<Data "{self.username}">' 

# Model for initiating SAW Method
class SAW(db.Model, SerializerMixin):
  __tablename__ = 'saw'
  
  serialize_only = ('id', 'name', 'description', 'data_id', 'created_at', 'updated_at')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String, nullable=False)
  description = db.Column(db.String)
  result_path = db.Column(db.String)
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  data_id = db.Column(db.Integer, db.ForeignKey('data.id'))
  saw_criteria = db.relationship('SAWCriteria', backref='saw')

  def __repr__(self):
    return f'<SAW "{self.name}">' 
  
""" 
Criteria and Crisp Models for SAW METHOD
"""
class SAWCriteria(db.Model, SerializerMixin):
  __tablename__ = 'saw_criteria'

  serialize_only = ('id', 'name', 'atribute', 'weight', 'crisp_type', 'saw_crisp.id')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String, nullable=False)
  atribute = db.Column(db.Integer, nullable=False) # 0 = Benefit, 1 = Cost
  weight = db.Column(db.Integer, nullable=False)
  crisp_type = db.Column(db.Integer, nullable=False) # 0 = Number, 1 = String, 2 = Sub String
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  saw_id = db.Column(db.Integer, db.ForeignKey('saw.id'))
  saw_crisp = db.relationship('SAWCrisp', backref='saw_criteria')

  def __repr__(self):
    return f'<SAWCriteria "{self.name}">'

class SAWCrisp(db.Model, SerializerMixin):
  __tablename__ = 'saw_crisp'

  serialize_only = ('id', 'name', 'detail', 'weight', 'saw_criteria_id')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String, nullable=False)
  detail = db.Column(db.String, nullable=False)
  weight = db.Column(db.Integer, nullable=False)
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  saw_criteria_id = db.Column(db.Integer, db.ForeignKey('saw_criteria.id'))

  def __repr__(self):
    return f'<SAWCrisp "{self.name}">'

# Model for initiating AHP Method
class AHP(db.Model, SerializerMixin):
  __tablename__ = 'ahp'

  serialize_only = ('id', 'name', 'description', 'created_at', 'updated_at')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String, nullable=False)
  description = db.Column(db.String)
  result_path = db.Column(db.String)
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  data_id = db.Column(db.Integer, db.ForeignKey('data.id'))
  ahp_criteria = db.relationship('AHPCriteria', backref='ahp')

  def __repr__(self):
    return f'<AHP "{self.name}">'
  
""" 
Criteria and Crisp Models for AHP METHOD
"""
class AHPCriteria(db.Model, SerializerMixin):
  __tablename__ = 'ahp_criteria'

  serialize_only = ('id', 'name', 'crisp_type', 'ahp_crisp.id')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.Integer, nullable=False)
  crisp_type = db.Column(db.Integer, nullable=False) # 0 = Number, 1 = String
  priority = db.Column(db.Float)
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  ahp_id = db.Column(db.Integer, db.ForeignKey('ahp.id'))
  ahp_importance_id = db.Column(db.Integer, db.ForeignKey('ahp_criteria_importance.id'))
  ahp_crisp = db.relationship('AHPCrisp', backref='ahp_criteria')
  
  def __repr__(self):
    return f'<AHPCriteria "{self.name}">'

class AHPCrisp(db.Model, SerializerMixin):
  __tablename__ = 'ahp_crisp'

  serialize_only = ('id', 'name', 'detail')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.Integer, nullable=False)
  detail = db.Column(db.String, nullable=False)
  priority = db.Column(db.Float)
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  ahp_criteria_id = db.Column(db.Integer, db.ForeignKey('ahp_criteria.id'))
  ahp_importance_id = db.Column(db.Integer, db.ForeignKey('ahp_crisp_importance.id'))

  def __repr__(self):
    return f'<AHPCrisp "{self.Name}">'

"""
Criteria and Crisp each has a different model
"""
class AHPCriteriaImportance(db.Model, SerializerMixin):
  __tablename__ = 'ahp_criteria_importance'

  serialize_only = ('id', 'importance')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  importance = db.Column(db.Float, nullable=False)
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  ahp_criteria = db.relationship('AHPCriteria', backref='ahp_criteria_importance')

  def __repr__(self):
    return f'<AHPCriteriaImportance Value: "{self.importance}">'

class AHPCrispImportance(db.Model, SerializerMixin):
  __tablename__ = 'ahp_crisp_importance'
  
  serialize_only = ('id', 'importance')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  importance = db.Column(db.Float, nullable=False)
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  ahp_crisp = db.relationship('AHPCrisp', backref='ahp_crisp_importance')

  def __repr__(self):
    return f'<AHPCrispImportance Value: "{self.importance}">'