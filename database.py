from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.sql import func

# Database Initialization
class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)

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

# DataDetail <--> MultiCriteria
datadetail_multicriteria = db.Table('datadetail_multicriteria',
  db.Column('datadetail_id', db.Integer, db.ForeignKey('datadetail.id')),
  db.Column('multicriteria_id', db.Integer, db.ForeignKey('multicriteria.id'))
)

# Models
class User(db.Model, SerializerMixin):
  __tablename__ = "user"

  serialize_only = ('id', 'username', 'password', 'created_at', 'updated_at', 'data.name')
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

  serialize_only = ('id', 'name', 'file_path', 'created_at', 'updated_at', 'user_id', 'datadetails.criteria')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String, nullable=False)
  file_path = db.Column(db.String, nullable=False)
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
  datadetails = db.relationship('DataDetail', backref='data')

  def __repr__(self):
    return f'<Data "{self.username}">' 
   
class DataDetail(db.Model, SerializerMixin):
  __tablename__ = "datadetail"

  serialize_only = ('id', 'criteria', 'type', 'data_id')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  criteria = db.Column(db.String)
  type = db.Column(db.String)
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  mcdetails = db.relationship('MultiCriteria', secondary=datadetail_multicriteria, backref='cdetails')
  data_id = db.Column(db.Integer, db.ForeignKey('data.id'))

  def __repr__(self):
    return f'<DataDetail "{self.name}">' 

class MultiCriteria(db.Model, SerializerMixin):
  __tablename__ = "multicriteria"

  serialize_only = ('id', 'name')
  serialize_rules = ()

  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String)
  created_at = db.Column(db.TIMESTAMP, server_default=func.now())
  updated_at = db.Column(db.TIMESTAMP, onupdate=func.current_timestamp())

  def __repr__(self):
    return f'<MultiCriteria "{self.name}">' 
