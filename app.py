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
import speech_recognition as sr
from werkzeug.utils import secure_filename

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

    nombre = nombre.lower()
    apellido_paterno = apellido_paterno.lower()
    apellido_materno = apellido_materno.lower()
    
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
    
#endpoint editar_perfil
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
    usuario = mongo.db.users.find_one({'_id': user_id})
    if not usuario:
        return jsonify({'message': 'Usuario no encontrado'}), 404

    # Diccionario vacío para almacenar los campos a actualizar
    datos_actualizados = {}

    # Validaciones de los campos opcionales
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
        datos_actualizados['nombre'] = nombre.lower()

    if apellido_paterno:
        if not re.match(r'^[a-zA-Z\s]+$', apellido_paterno):
            return jsonify({'message': 'Apellido paterno debe contener solo caracteres alfabéticos y espacios'}), 400
        datos_actualizados['apellido_paterno'] = apellido_paterno.lower()

    if apellido_materno:
        if not re.match(r'^[a-zA-Z\s]+$', apellido_materno):
            return jsonify({'message': 'Apellido materno debe contener solo caracteres alfabéticos y espacios'}), 400
        datos_actualizados['apellido_materno'] = apellido_materno.lower()

    if email:
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'message': 'Formato de correo electrónico invalido'}), 400
        datos_actualizados['email'] = email

    if password:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        datos_actualizados['password'] = hashed_password

    # Actualización en la base de datos
    result = mongo.db.users.update_one(
        {'_id': user_id},  # Filtro
        {'$set': datos_actualizados},  # Actualización
    )

    if result.modified_count > 0:
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
    
    #convertir nombre del archivo a minusculas
    nombre_archivo = archivo.filename.lower() #archivo.filename = nombre del archivo
    base_name, extension = os.path.splitext(nombre_archivo) #se utiliza para dividir el nombre del archivo y la extension 
    
    #os.path.join() crea la ruta completa donde se guardará el archivo
    path_archivo = os.path.join(app.config['UPLOAD_FOLDER'], categoria,nombre_archivo) #combina la carpeta de subida (UPLOAD_FOLDER que contiene la ruta base de la carpeta uploads), con la categoria y con el nombre del archivo 

    # Generar un nuevo nombre si el archivo ya existe
    contador = 1
    while os.path.exists(path_archivo):
        nuevo_nombre = f"{base_name}_{contador}{extension}"
        path_archivo = os.path.join(app.config['UPLOAD_FOLDER'], categoria, nuevo_nombre)
        contador += 1

    #verificar que no exista un video con el mismo nombre en la misma categoria en la base de datos
    video = mongo.db.videos.find_one({
        'categoria': categoria, 
        'user_id': user_id,
        'archivo': nombre_archivo
    })
    if video:
        return jsonify({'message': 'Ya existe un video con ese nombre en la categoria'})
    
    archivo.save(path_archivo) #guarda el arhcivo en la carpeta

    uploaded = mongo.db.videos.insert_one({
        'archivo': nombre_archivo,
        "ruta_del_archivo": path_archivo,
        "user_id": user_id,
        "categoria": categoria
    })

    return jsonify({
        'message': 'Archivo subido correctamente',
        'id': str(uploaded.inserted_id),
        'nombre_archivo': nombre_archivo,
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
    
    nombre_archivo = nombre_archivo.lower()
    
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

    #para poder iterar correctamente toda la consulta
    lista_videos = list(videos) 

    if not lista_videos:
        return jsonify({'message': 'No se encontró ningún video'}), 404

    videos_response = [
        {
            'archivo': video['archivo'],
            'ruta_del_archivo': video['ruta_del_archivo'],
            'user_id': str(user_id),
            '_id': str(video['_id'])
        }
        for video in lista_videos
    ]

    return jsonify({
        'videos': videos_response
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
    
    categoria = categoria.lower()

    videos = mongo.db.videos.find({
        'user_id': user_id,
        'categoria': categoria
    })

    categories = ['abecedario', 'casa', 'comida', 'deportes', 'familia', 'numeros']
    if categoria not in categories:
        return jsonify({'message': 'La categoria no existe'}), 400

    lista_videos = list(videos)

    if not lista_videos:
        return jsonify({'message': 'No se encontraron videos'}), 404
    
    videos_response = [
        {
            'archivo': video['archivo'],
            'ruta_del_archivo': video['ruta_del_archivo'],
            'user_id': str(user_id),
            '_id': str(video['_id'])
        }
        for video in lista_videos
    ]

    return jsonify({
        'videos': videos_response
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
    
    nombre_video = nombre_video.lower()
    categoria = categoria.lower()
    
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
    
    nombre_video = nombre_video.lower()
    categoria = categoria.lower()

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

#endpoint crear nombre propio abecededario y que se reproduzca en lenguaje de señas
@app.route('/crear_nombre_abecedario', methods=['POST'])
@jwt_required()
def crear_nombre_abecedario():
    data = request.get_json()
    nombre = data.get('nombre')
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'El usuario no existe'}), 404
    
    if not nombre:
        return jsonify({'message': 'No se proporcionó el nombre'}), 400

    if not re.match(r'^[a-zA-Z\s]+$', nombre):
        return jsonify({'message': 'El nombre solo puede contener letras y espacios'}),400
    
    nombre = nombre.lower()

    if mongo.db.nombres.find_one({
        'nombre': nombre,
        'user_id': user_id
    }):
        return jsonify({'message': 'El nombre ya existe'}), 400
    
    lista_videos = []

    #.mov por ahorita de la mac
    for letra in nombre:
        buscar_video = mongo.db.videos.find_one({
            'user_id': user_id,
            'archivo': letra + '.mov', 
            'categoria': 'abecedario'
        })
        if not buscar_video:
            return jsonify({'message': f'No existe un video para la letra {letra}'}), 404
        
        # Convertir _id y user_id a cadena y añadir el video a la lista
        buscar_video['_id'] = str(buscar_video['_id'])
        buscar_video['user_id'] = str(buscar_video['user_id'])

        # Verificar si el archivo realmente existe en el sistema de archivos
        path_archivo = os.path.join('uploads', 'abecedario', buscar_video['archivo'])
        if not os.path.exists(path_archivo):
            return jsonify({'message': f'El video para la letra {letra} no se encuentra en la carpeta'}), 404

        lista_videos.append(buscar_video)

    #crear un documento que contenga el nombre creado y los videos asociados
    nombre_data ={
        'user_id': ObjectId(user_id),
        'nombre': nombre,
        'videos': lista_videos
    }

    #insertarlo en la coleccion nombres
    result = mongo.db.nombres.insert_one(nombre_data)

    return jsonify({
        'message': 'Se ha creado el nombre y se ha guardado',
        '_id_nombre': str(result.inserted_id),
        'nombre': nombre,
        'videos': lista_videos
    }), 200

#endpoint obtener nombre creado del usuario
@app.route('/nombre/<nombre>', methods=['GET'])
@jwt_required()
def obtener_nombre(nombre):
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontro el usuario'}), 404
    
    nombre = nombre.lower()
    
    nombre_data = mongo.db.nombres.find_one({
        'user_id' : user_id,
        'nombre': nombre
    })

    if not nombre_data:
        return jsonify({'message': 'No se encontro el nombre'}), 404
    
    return jsonify({
        'user_id': str(user_id),
        'nombre': nombre_data['nombre'],
        'videos': nombre_data['videos']
    }), 200

#endpoint mostrar todos los nombres guardados del usuario
@app.route('/nombres', methods=['GET'])
@jwt_required()
def mostrar_nombres():
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontro el usuario'}), 404
    
    nombres = mongo.db.nombres.find({'user_id': user_id})

    lista_nombres = list(nombres)
    if not lista_nombres:
        return jsonify({'message': 'No se encontro ningun nombre'}), 404

    videos_response = [
        {
            'nombre': nombre['nombre'],
            'videos': nombre['videos'],
            'user_id': str(nombre['user_id']),
            '_id': str(nombre['_id'])
        }
        for nombre in lista_nombres
    ]

    return jsonify(videos_response)

#endpoint borrar un nombre creado
@app.route('/borrar_nombre/<nombre>', methods=['DELETE'])
@jwt_required()
def borrar_nombre(nombre):
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontro el usuario'}), 404
    
    nombre = nombre.lower()
    
    nombre_data = mongo.db.nombres.find_one({
        'user_id': user_id,
        'nombre': nombre
    })

    if not nombre_data:
        return jsonify({'message': 'No se encontro el nombre que se quiere eliminar'}), 404
    
    result = mongo.db.nombres.delete_one({
        'user_id': user_id,
        'nombre': nombre
    })

    if result.deleted_count > 0:
        return jsonify({'message': 'Nombre eliminado con exito'}), 200
    else:
        return jsonify({'message': 'No se pudo eliminar el nombre'}), 400

if __name__ == '__main__':
    app.run(debug=True)