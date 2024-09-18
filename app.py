from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import mongo, init_db
from config import Config
from flask_bcrypt import Bcrypt
from bson.json_util import ObjectId
from datetime import timedelta, datetime
import re

app = Flask(__name__)
app.config.from_object(Config)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1) #configura el tiempo de expiracion GLOBAl del token a 1 hr
#JWT_ACCESS_TOKEN_EXPIRES es lo que usa flask_jwt_extended para manejar el tiempo global del token

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

init_db(app)

#endpoint para registrar a un usuario
@app.route('/registrar', methods=['POST'])
def registrar():
    data = request.get_json()
    nombre = data.get('nombre')
    apellido_paterno = data.get('apellido_paterno')
    apellido_materno = data.get('apellido_materno')
    email = data.get('email')
    password = data.get('password')
    fecha_nacimiento = data.get('fecha_nacimiento') #opcional
    celular = data.get('celular') #opcional
    
    #verifica que los campos obligatorios si esten
    if not nombre or not apellido_materno or not apellido_paterno or not email or not password:
        return jsonify({'message': 'Nombre, apellidos, email y contraseña son requeridos'}), 400
    
    if mongo.db.users.find_one({
        'email': email
    }):
        return jsonify({'message': 'El usuario ya existe'}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    #prepara los datos (crea un diccionario (pares clave-valor))
    user_data = {
        'nombre': nombre,
        'apellido_paterno' : apellido_paterno,
        'apellido_materno' : apellido_materno,
        'email': email,
        'password': hashed_password
    }

    #VALIDAR
    if not re.match(r'^[a-zA-Z\s]+$', nombre):
        return jsonify({'message': 'Nombre debe contener solo caracteres alfabéticos y espacios'}), 400
    if not re.match(r'^[a-zA-Z\s]+$', apellido_paterno):
        return jsonify({'message': 'Apellido paterno debe contener solo caracteres alfabéticos y espacios'}), 400
    if not re.match(r'^[a-zA-Z\s]+$', apellido_materno):
        return jsonify({'message': 'Apellido materno debe contener solo caracteres alfabéticos y espacios'}), 400
    
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({'message': 'Email debe ser válido'}), 400
    
    #si se proporciona la fecha de nacimiento se hara todo
    if fecha_nacimiento: 
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', fecha_nacimiento):
            return jsonify({'message': 'Fecha de nacimiento debe ser en formato YYYY-MM-DD'}), 400
        
    if celular:
        if not re.match(r'^\d{10}$', celular):
            return jsonify({'message': 'Celular debe ser válido (10 dígitos)'}), 400

    if fecha_nacimiento:
        user_data['fecha_nacimiento'] = fecha_nacimiento #se guarda en el diccionario
    if celular:
        user_data['celular'] = celular

    result = mongo.db.users.insert_one(user_data)

    if result.acknowledged:
        return jsonify({'message': 'Usuario creado con exito'}), 200
    else:
        return jsonify({'message': 'Error al crear el usuario'}), 500
    
    
    
#endpoint para login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Faltan campos'}), 400

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
    
#endpoint editar datos usuario
@app.route('/editarPerfil', methods=['PUT'])
@jwt_required()
def editarPerfil():
    data = request.get_json()
    celular = data.get('celular')
    fecha_nacimiento = data.get('fecha_nacimiento')
    nombre = data.get('nombre')
    apellido_paterno = data.get('apellido_paterno')
    apellido_materno = data.get('apellido_materno')
    user_id = get_jwt_identity()

    user_id = ObjectId(user_id)

    #diccionario vacio
    datos_actualizados = {}

    if celular:
        if not re.match(r'^\d{10}$', celular):
            return jsonify({'message': 'Formato de celular invalido (10 dígitos)'}), 400
        datos_actualizados['celular'] = celular
        
    if fecha_nacimiento:
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', fecha_nacimiento):
            return jsonify({'message': 'Fecha de nacimiento debe ser en formato YYYY-MM-DD'}), 400
        datos_actualizados['fecha_nacimiento'] = fecha_nacimiento

    if nombre:
        if not re.match(r'^[a-zA-Z\s]+$', nombre):
            return jsonify({'message': 'Nombre debe contener solo caracteres alfabéticos y espacios'}), 400
        datos_actualizados['nombre'] = nombre

    if apellido_paterno:
        if not re.match(r'^[a-zA-Z\s]+$', apellido_paterno):
            return jsonify({'message': 'Apellido paterno debe contener solo caracteres alfabéticos y espacios'}), 400
        datos_actualizados['apellido_paterno'] = apellido_paterno

    if apellido_materno:
        if not re.match(r'^[a-zA-Z\s]+$', apellido_materno):
            return jsonify({'message': 'Apellido materno debe contener solo caracteres alfabéticos y espacios'}), 400
        datos_actualizados['apellido_paterno'] = apellido_paterno

    result = mongo.db.users.update_one(
        {'_id': user_id}, #filtro, lo que va a buscar
        {'$set': datos_actualizados}, #actualizacion, lo que actualizara
    )

    if result.modified_count > 0: #si la cuenta de cosas moficiadas es mayor a cero signifca que al menos un campo se actualizó 
        return jsonify({'message': 'Datos actualizados correctamente'}), 200
    else:
        return jsonify({'message': 'No se actualizaron datos'}), 400

if __name__ == '__main__':
    app.run(debug=True)