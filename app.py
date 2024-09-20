import os
from flask import Flask, request, jsonify, send_file
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import mongo, init_db
from config import Config, ConfigGmail, ConfigOutlook
from flask_bcrypt import Bcrypt
from bson.json_util import ObjectId
from datetime import timedelta, datetime
import re
from flask_mail import Mail, Message

app = Flask(__name__)

#configuracion para conexion mongo, jwt y ruta videos
app.config.from_object(Config)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
#configuracion para gmail
app.config.from_object(ConfigGmail)
mail_gmail = Mail(app)
#configuracion para outlook
app.config.from_object(ConfigOutlook)
mail_outlook = Mail(app)

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
    
    #llama a la funcion para validar el dominio del correo
    if not validar_dominio(email):
        return jsonify({'message': 'El correo debe ser gmail, outlook o hotmail'}), 400
    
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
    
def validar_dominio(email):
    return email.endswith('@gmail.com') or email.endswith('@outlook.com') or email.endswith('@hotmail.com')
    
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
        access_token = create_access_token(identity=str(user["_id"]), expires_delta=timedelta(hours=1)) #expira el token en 1 hr
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
    email = data.get('email')
    password = data.get('password')
    apellido_paterno = data.get('apellido_paterno')
    apellido_materno = data.get('apellido_materno')
    user_id = get_jwt_identity()

    user_id = ObjectId(user_id)

    if not data:
        return jsonify({'message': 'No se recibieron datos para actualizar'}), 400
    
    # Verificamos si el usuario existe
    usuario = mongo.db.users.find_one({
        '_id': user_id
    })
    if not usuario:
        return jsonify({
            'message': 'Usuario no encontrado'
        }), 404

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

    if email:
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'message': 'Formato de correo electrónico invalido'}), 400
        datos_actualizados['email'] = email

    if password:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        datos_actualizados['password'] = hashed_password

    result = mongo.db.users.update_one(
        {'_id': user_id}, #filtro, lo que va a buscar
        {'$set': datos_actualizados}, #actualizacion, lo que actualizara
    )

    if result.modified_count > 0: #si la cuenta de cosas moficiadas es mayor a cero signifca que al menos un campo se actualizó 
        return jsonify({'message': 'Datos actualizados correctamente'}), 200
    else:
        return jsonify({'message': 'No se actualizaron datos'}), 400

#endpoint para eliminar cuenta
@app.route('/eliminar_cuenta', methods=['DELETE'])
@jwt_required()
def eliminar_cuenta():
    data = request.get_json()
    password = data.get('password') #se necesitara la contraseña para eliminar la cuenta
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)

    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No existe el usuario'}), 404
    
    if not password:
        return jsonify({'message': 'Debes proporcionar la contraseña para eliminar la cuenta'}), 400

    if not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'message': 'Contraseña incorrecta'}), 400

    result = mongo.db.users.delete_one({'_id': user_id})

    if result.deleted_count > 0:
        return jsonify({'message': 'Cuenta eliminada correctamente'}), 200
    else:
        return jsonify({'message': 'No se pudo eliminar la cuenta'}), 400

#endpoint solicitar reestablecer contraseña
@app.route('/solicitarRestablecerContraseña', methods=['POST'])
def solicitarRestablecerContraseña():
    data = request.get_json()
    email = data.get('email')

    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'No se encontro un usuario con ese email'}), 404
    
    reset_token = create_access_token(identity=str(user['_id']), expires_delta=timedelta(hours=1))

    #envia el token al correo del usuario
    reset_link = f"http://signia_beta/restaurar_contraseña/{reset_token}" #este sera el link el cual contendra el token
    send_email(email, 'Restablecer tu contraseña', f'Usa este enlance para restablecer tu contraseña: {reset_link}') #llamara a la
    #funcion que envia el correo

    return jsonify({
        'message': 'Se ha enviado un correo con el enlace para restablecer tu contraseña'
    }), 200

#funcion para mandar el correo
#Message construye el correo
#primero va el subject (asunto)
#el destinatario debe estar en una lista
#y por ultimo el cuerpo
def send_email(destinatario, asunto, cuerpo, provider="gmail"): #se pone por default gmail p
    if provider == "gmail":
        msg = Message(subject=asunto, recipients=[destinatario], body=cuerpo, sender=app.config['MAIL_DEFAULT_SENDER']) #sender=app.config['MAIL_DEFAULT_SENDER'] especifica quien manda el correo
        mail_gmail.send(msg) #envia el correo
    elif provider == "outlook":
        msg = Message(subject=asunto, recipients=[destinatario], body=cuerpo, sender=app.config['MAIL_DEFAULT_SENDER'])
        mail_outlook.send(msg)

#endpoint restablecer contraseña
@app.route('/restaurar_contraseña', methods=['POST'])
@jwt_required()
def restaurar_contraseña():
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    data = request.get_json()
    password = data.get('password')

    if not password:
        return jsonify({'message': 'Tienes que poner una contraseña nueva'}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    user = mongo.db.users.find_one({'_id': user_id})

    if not user:
        return jsonify({'message': 'No se encontro un usuario con ese id'}), 404
    else:
        mongo.db.users.update_one({'_id': user_id}, {'$set': {'password': hashed_password}})
        return jsonify({'message': 'Contraseña restablecida'}), 200
    
#endpoint subir videos
@app.route('/subir_video/<categoria>', methods=['POST'])
@jwt_required()
def subir_video(categoria):
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontro un usuario'}), 404

    #request_files contiene todos los archivos
    #checa si hay algun archivo enviado con la clave 'archivo'
    if 'archivo' not in request.files:
        return jsonify({'message': 'No hay ningun archivo'}), 400
    
    #si si hay un archivo con esa clave se guarda
    archivo = request.files['archivo']
    #si el valor de esa clave esta vacio manda el msg
    if archivo.filename == '':
        return jsonify({'message': 'No se ha seleccionado un archivo'}), 400
    
    #verificar que la categoria existe
    categories = ['abecedario', 'casa', 'comida', 'deportes', 'familia', 'numeros']
    if categoria not in categories:
        return jsonify({'message': 'La categoria no existe'}), 400
    
    #os.path.join() crea la ruta completa donde se guardará el archivo
    path_archivo = os.path.join(app.config['UPLOAD_FOLDER'], categoria,archivo.filename) #combina la carpeta de subida (UPLOAD_FOLDER que contiene la ruta base de la carpeta uploads), con la categoria y con el nombre del archivo (file.filename)

    #verificar que no exista un video con el mismo nombre en la misma categoria en la base de datos
    video = mongo.db.videos.find_one({'categoria': categoria, 'archivo': archivo.filename})
    if video:
        return jsonify({'message': 'Ya existe un video con ese nombre en la categoria'})
    
    #verificar que no exista un video con el mismo nombre en la misma categoria en las carpetas
    if os.path.exists(path_archivo):
        return jsonify({'message': 'Ya existe un video con ese nombre en la categoria'})
    
    archivo.save(path_archivo) #guarda el arhcivo en la carpeta

    uploaded = mongo.db.videos.insert_one({
        'archivo': archivo.filename,
        "ruta_del_archivo": path_archivo,
        "user_id": user_id,
        "categoria": categoria
    })

    return jsonify({
        'message': 'Archivo subido correctamente',
        'id': str(uploaded.inserted_id),
        'nombre_archivo': archivo.filename,
        'ruta': path_archivo,
        'id_user': str(user_id),
        'categoria': categoria
    }), 201

#endpoint obtener video por nombre
@app.route('/obtener_video/<nombre_archivo>', methods=['GET'])
@jwt_required()
def obtener_videos(nombre_archivo):
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontro un usuario'}), 404
    
    video = mongo.db.videos.find_one({
        'archivo': nombre_archivo,
        'user_id': user_id
    })

    if not video:
        return jsonify({'message': 'No se encontro el video'}), 404
    
    ruta_video = video['ruta_del_archivo']

    #comprobar que el video exista en la carpeta
    if not os.path.exists(ruta_video):
        return jsonify({'message': 'El archivo no existe'}), 404

    return jsonify({
        'message': 'Video encontrado',
        'ruta': ruta_video
    }), 200

    #return send_file(ruta_video) para enviar el archivo del video

#endpoint obtener todos los videos del usuario
@app.route('/mis_videos', methods=['GET'])
@jwt_required()
def mis_videos():
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontro un usuario'}), 404
    
    #obtener videos del usuario
    videos = mongo.db.videos.find({
        'user_id': user_id
    })

    if not videos:
        return jsonify({'message': 'No se encontro ningun video'}), 404

    lista_videos = []

    for video in videos:
        lista_videos.append({
            'archivo': video['archivo'],
            'ruta_del_archivo': video['ruta_del_archivo'],
            'user_id': str(user_id),
            '_id': str(video['_id'])
        })

    return jsonify({
        'videos': lista_videos
    }), 200

#endpoint bsucar palabras por categoria
@app.route('/buscar_por_categoria/<categoria>', methods=['GET'])
@jwt_required()
def buscar(categoria):
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)

    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontro un usuario'}), 404

    videos = mongo.db.videos.find({
        'user_id': user_id,
        'categoria': categoria
    })

    if not videos:
        return jsonify({'message': 'No se encontro ningun video'}), 404

    lista_videos = []

    for video in videos:
        lista_videos.append({
            'archivo': video['archivo'],
            'ruta_del_archivo': video['ruta_del_archivo'],
            'user_id': str(user_id),
            '_id': str(video['_id'])
        })

    return jsonify({
        'videos': lista_videos
    })

#endpoint borrar video
@app.route('/borrar_video/<categoria>/<nombre_video>', methods=['DELETE'])
@jwt_required()
def borrar_video(categoria,nombre_video):
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontro un usuario'}), 404
    
    video = mongo.db.videos.find_one({
        'user_id': user_id,
        'archivo': nombre_video,
        'categoria': categoria
    })

    if not video:
        return jsonify({'message': 'No se encontro el video'}), 404
    
    ruta_archivo = video['ruta_del_archivo']
    
    #Borrar el video del usuario con la categoría
    resultado = mongo.db.videos.delete_one({
        'user_id': user_id,
        'archivo': nombre_video,
        'categoria': categoria
    })

    if resultado.deleted_count > 0:
        if os.path.exists(ruta_archivo): #verifica si el archivo especificado en ruta_archivo realmente existe en el sistema
            os.remove(ruta_archivo) # Eliminar el archivo del sistema de archivos
        return jsonify({'message': 'Video eliminado con exito'}), 200
    else:
        return jsonify({'message': 'No se pudo eliminar el video'}), 400
    
#endpoint para actualizar video
@app.route('/actualizar_video/<categoria>/<nombre_video>', methods=['PUT'])
@jwt_required()
def actualizar_video(categoria, nombre_video):
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontró un usuario'}), 404
    
    categories = ['abecedario', 'casa', 'comida', 'deportes', 'familia', 'numeros']
    if categoria not in categories:
        return jsonify({'message': 'La categoría no existe'}), 400

    video = mongo.db.videos.find_one({
        'user_id': user_id,
        'archivo': nombre_video,
        'categoria': categoria
    })

    if not video:
        return jsonify({'message': 'No se encontró el video'}), 404
    
    ruta_archivo_existente = video['ruta_del_archivo']
    
    if 'archivo' not in request.files:
        return jsonify({'message': 'No hay archivo'}), 400
    
    archivo = request.files['archivo']
    if archivo.filename == '':
        return jsonify({'message': 'No se seleccionó un archivo'}), 400

    # Eliminar el archivo existente si se encuentra 
    if os.path.exists(ruta_archivo_existente):
        os.remove(ruta_archivo_existente)

    # Guardar el nuevo archivo
    path_archivo = os.path.join(app.config['UPLOAD_FOLDER'], categoria, archivo.filename)
    archivo.save(path_archivo)

    # Actualizar la base de datos
    resultado = mongo.db.videos.update_one(
        {'user_id': user_id, 'archivo': nombre_video, 'categoria': categoria},
        {'$set': {'archivo': archivo.filename, 'ruta_del_archivo': path_archivo}}
    )

    if resultado.modified_count > 0:
        return jsonify({'message': 'Video actualizado con éxito'}), 200
    else:
        return jsonify({'message': 'No se pudo actualizar el video'}), 400


if __name__ == '__main__':
    app.run(debug=True)