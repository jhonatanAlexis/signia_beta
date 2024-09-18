from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import mongo, init_db
from config import Config
from flask_bcrypt import Bcrypt
from bson.json_util import ObjectId

app = Flask(__name__)
app.config.from_object(Config)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

init_db(app)

#endpoint para registrar a un usuario
@app.route('/registrar', methods=['POST'])
def registrar():
    data = request.get_json()
    nombre = data.get('nombre')
    email = data.get('email')
    password = data.get('password')

    if mongo.db.users.find_one({
        'email': email
    }):
        return jsonify({'message': 'El usuario ya existe'}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    result = mongo.db.users.insert_one({
        'nombre': nombre,
        'email': email,
        'password': hashed_password
    })
    if result.acknowledged:
        return jsonify({'message': 'Usuario creado con exito'}), 200
    else:
        return jsonify({'message': 'Error al crear el usuario'}), 500
    
#endpoint para login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    nombre = data.get('nombre')
    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({
        'email': email
    })

    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify({
            'access_token': access_token,
        }), 200
    else:
        return jsonify({'message': 'Credenciales invalidas'}), 401
    
#endpoint para obtener datos del usuario
@app.route('/yo', methods=['GET'])
@jwt_required()
def yo():
    user_id = get_jwt_identity()

    user_id = ObjectId(user_id)

    usuario = mongo.db.users.find_one({
        '_id': user_id
    },{
        'password': 0
    })

    if usuario:
        usuario['_id'] = str(usuario['_id'])
        return jsonify(usuario), 200
    else:
        return jsonify({'message': 'Usuario no encontrado'}), 404

if __name__ == '__main__':
    app.run(debug=True)