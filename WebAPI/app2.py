from datetime import timedelta
import shutil
import bcrypt
import os
    
from flask import Flask, jsonify, request, Response, render_template, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from sqlalchemy.exc import IntegrityError, OperationalError
import re

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/celik/test8.db'
db = SQLAlchemy(app)
app.config["JWT_SECRET_KEY"] = "keyimmmm"  # Güçlü bir secret key kullanın!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=30)  # Token süresi 1 ay
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)  # Şifreler için uygun uzunluk seçin

class Fonksiyonlar:
    def __init__(self):
        with app.app_context():
            db.create_all()
            self.users = User.query.all()

    def get_users(self):
        @jwt_required()
        def protected_get_users():
            current_user_id = get_jwt_identity()
            return jsonify([
                {'id': user.id, 'username': user.username, 'email': user.email} 
                for user in self.users
            ])
        return protected_get_users()

    def get_user(self, user_id):
        user = User.query.get(user_id)
        if user:
            return jsonify({
                'id': user.id,
                'username': user.username,
                'email': user.email
            })
        else:
            return jsonify({'message': 'User not found'}), 404

    def create_user(self):
        data = request.get_json()
        try:
            if not self.validate_user_data(data):
                return jsonify({'message': 'Invalid user data'}), 400
            new_user = User(username=data['username'], email=data['email'], password=data['password'])
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'User created successfully'}), 201
        except IntegrityError:
            return jsonify({'message': 'Email address already exists'}), 409
        except Exception as e:
            print(f"Hata oluştu: {e}")
            return jsonify({'message': 'User creation failed'}), 500

    def update_user(self, user_id):
        data = request.get_json()
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        try:
            if not self.validate_user_data(data):
                return jsonify({'message': 'Invalid user data'}), 400
            user.username = data['username']
            user.email = data['email']
            user.password = data['password']  # Şifre güncelleme işlemini güvenli bir şekilde yapın
            db.session.commit()
            return jsonify({'message': 'User updated successfully'})
        except IntegrityError:
            return jsonify({'message': 'Email address already exists'}), 409
        except Exception as e:
            print(f"Hata oluştu: {e}")
            return jsonify({'message': 'User update failed'}), 500

    def delete_user(self, user_id):
        user = User.query.get_or_404(user_id)
        try:
            db.session.delete(user)
            db.session.commit()
            user_folder = os.path.join('static/users', user.username)
            shutil.rmtree(user_folder)
            
            return jsonify({'message': 'User deleted successfully'})
        except OperationalError as e: 
            print(f"Hata oluştu: {e}") 
            return jsonify({'message': 'User deletion failed'}), 500

    def generate_token(self, user_id):
        access_token = create_access_token(identity=user_id) 
        return access_token

    def index(self):
        return redirect("static/index.html")

    def register(self):
        data = request.get_json()
        try:
            if not self.validate_user_data(data):
                return jsonify({'message': 'Invalid user data'}), 400
            hashed_password = self.hash_password(data['password'])
            new_user = User(username=data['username'], email=data['email'], password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            
            user_folder = os.path.join('static/users', data['username'])
            
            os.makedirs(user_folder, exist_ok=True)  # Klasör zaten varsa hata verme
            
            source_file = os.path.join('ornekler', 'anasayfa.html')
            destination_file = os.path.join(user_folder, 'anasayfa.html')
            shutil.copy2(source_file, destination_file)
            
            anasayfa_url = url_for('static', filename=os.path.join("users", data['username']))
            #return jsonify(access_token=access_token)
            return redirect("static/giris.html")
            #return jsonify({'message': 'User created successfully'}), 201
        except IntegrityError:
            return jsonify({'message': 'Email address already exists'}), 409
        except Exception as e:
            print(f"Hata oluştu: {e}")
            return jsonify({'message': 'User creation failed'}), 500

    def login(self):
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and self.check_password(user.password, password):
            #access_token = self.generate_token(user.id)
            user_folder = os.path.join('users', username)
            anasayfa_url = url_for('static', filename=os.path.join(user_folder, 'anasayfa.html'))
            #return jsonify(access_token=access_token)
            return redirect(anasayfa_url)
        else:
            return jsonify({"msg": "Bad username or password"}), 401
            
    def validate_user_data(self, data):
        # Temel doğrulama örneği (daha kapsamlı doğrulama ekleyebilirsiniz)
        if not all(key in data for key in ['username', 'email', 'password']):
            return False
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", data['email']):
            return False
        return True 

    def hash_password(self, password):
        salt = bcrypt.gensalt()  # Rastgele salt oluştur
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')  # Byte dizisini stringe dönüştür

    def check_password(self, hashed_password, password):
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

f = Fonksiyonlar()

@app.route('/')
def index():
    return f.index()

@app.route('/login', methods=['POST'])
def login():
    return f.login()

@app.route('/register', methods=['POST'])
def register():
    return f.register()

@app.route("/get_users", methods=["GET"])
def get_users():
    return f.get_users()

@app.route('/get_user/<int:user_id>')
def get_user(user_id):
    return f.get_user(user_id)

@app.route("/create_user", methods=["POST"])
def create_user():
    return f.create_user()

@app.route("/update_user/<int:user_id>", methods=["PUT"]) 
def update_user(user_id):
    return f.update_user(user_id)

@app.route("/delete_user/<int:user_id>", methods=["DELETE"]) 
def delete_user(user_id):
    return f.delete_user(user_id)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
