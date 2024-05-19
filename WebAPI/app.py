from flask import Flask, jsonify, request, Response,render_template,redirect




from DB import User,db,app,auth

class Fonksiyonlar:
    def __init__(self):
		
        with app.app_context():
            db.create_all()
            self.users = User.query.all()


    def get_users(self):
        return jsonify([{'id': user.id, 'name': user.name, 'surname': user.surname, 'department': user.department, 'classNo': user.classNo} for user in self.users])

    def get_user(self, user_id):
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404
        return jsonify({'id': user.id, 'name': user.name, 'surname': user.surname, 'department': user.department, 'classNo': user.classNo})

    def create_user(self):
        data = request.get_json()
        new_user = User(name=data['name'], surname=data['surname'], department=data['department'], classNo=data['classNo'])
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully'}), 201

    def update_user(self, user_id):
        data = request.get_json()
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404
        user.name = data['name']
        user.surname = data['surname']
        user.department = data['department']
        user.classNo = data['classNo']
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})

    def delete_user(self, user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
        
    def index(self):
        return redirect("static/index.html")#render_templates('index.html')      #"Hello, %s!" % auth.username()


    def login(self):
        username = request.form['username']
        password = request.form['password']
        # Burada kullanıcı adı ve şifre ile giriş yapma işlemleri yapılabilir
        return f'Kullanıcı adı: {username}, Şifre: {password}'


    def register(self):
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        # Burada kayıt olma işlemleri yapılabilir
        return f'Kullanıcı adı: {username}, E-posta: {email}, Şifre: {password}'

		
		
f=Fonksiyonlar()


@app.route('/')
def index():
    return f.index()
    
    
    
@app.route('/login', methods=['POST'])
def login():
    return f.login()

@app.route('/register', methods=['POST'])
def register():
    return f.register()


@app.route("/get_users",methods=["GET"])    
def get_users():
    return f.get_users();

@app.route("/create_user",methods=["POST"])  
def create_user():

        return f.create_user()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    #app.run(debug=True)
    app.run(host='0.0.0.0', port=5000,debug=True)
