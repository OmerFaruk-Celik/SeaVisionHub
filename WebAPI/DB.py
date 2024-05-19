from flask import Flask, jsonify, request
from flask_httpauth import HTTPTokenAuth
from flask_sqlalchemy import SQLAlchemy
from flask import send_file


#app = Flask(__name__)
app = Flask(__name__, static_folder='static',template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/celik/test7.db'
db = SQLAlchemy(app)
auth = HTTPTokenAuth(scheme='Bearer')
app.config['SECRET_KEY'] = "ali" #os.getenv('SECRET_KEY')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)  
