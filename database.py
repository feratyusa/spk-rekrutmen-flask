from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy_serializer import SerializerMixin

# Database Initialization
class Base(DeclarativeBase):
  pass

Database = SQLAlchemy(model_class=Base)

# Models
class User(Database.Model, SerializerMixin):
    id: Mapped[int] = mapped_column(Database.Integer, primary_key=True)
    username: Mapped[str] = mapped_column(Database.String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(Database.String)
    email: Mapped[str] = mapped_column(Database.String)