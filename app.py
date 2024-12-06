import os
import cloudinary.exceptions
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import mongo, init_db
from config import Config, ConfigGmail, CloudConfig
from flask_bcrypt import Bcrypt
from bson.json_util import ObjectId
from datetime import datetime, timezone, timedelta
import re
from flask_mail import Mail, Message
import cloudinary
import cloudinary.uploader
import cloudinary.api
import cloudinary.search
import random
from moviepy import concatenate_videoclips, VideoFileClip
import tempfile

app = Flask(__name__)

# Configuración de la app (MongoDB, JWT, Flask-Mail)
app.config.from_object(Config)
app.config.from_object(ConfigGmail)

# Cargar la configuración de Cloudinary usando las variables de CloudConfig
cloudinary.config(
    cloud_name=CloudConfig.CLOUD_NAME,
    api_key=CloudConfig.API_KEY,
    api_secret=CloudConfig.API_SECRET
)

# Inicializa la base de datos
init_db(app)

# Inicializa Bcrypt y JWTManager
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Inicializa Flask-Mail
mail_gmail = Mail(app)

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
    rol = data.get('rol', 'user') #opcional y por defecto sera user

    #convierte a minusculas solo si no es none
    nombre = nombre.lower() if nombre else None
    apellido_paterno = apellido_paterno.lower() if apellido_paterno else None
    apellido_materno = apellido_materno.lower() if apellido_materno else None
    
    #verifica que los campos obligatorios si esten
    if not nombre or not apellido_materno or not apellido_paterno or not email or not password:
        return jsonify({'message': 'Nombre, apellido paterno, apellido materno, email y contraseña son requeridos'}), 400
    
    if rol not in ['admin', 'user']:
        return jsonify({'message': 'Rol inválido. Debe ser "admin" o "user" En minuscula'}), 400
    
    if mongo.db.users.find_one({
        'email': email
    }):
        return jsonify({'message': 'El usuario ya está registrado'}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    #prepara los datos (crea un diccionario (pares clave-valor))
    user_data = {
        'nombre': nombre,
        'apellido_paterno' : apellido_paterno,
        'apellido_materno' : apellido_materno,
        'email': email,
        'password': hashed_password,
        'rol': rol
    }

    #VALIDAR
    if not re.match(r'^[a-zA-Z\s]+$', nombre):
        return jsonify({'message': 'Nombre debe contener solo caracteres alfabéticos y espacios'}), 400
    if not re.match(r'^[a-zA-Z\s]+$', apellido_paterno):
        return jsonify({'message': 'Apellido paterno debe contener solo caracteres alfabéticos y espacios'}), 400
    if not re.match(r'^[a-zA-Z\s]+$', apellido_materno):
        return jsonify({'message': 'Apellido materno debe contener solo caracteres alfabéticos y espacios'}), 400
    
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({'message': 'El formato de correo electrónico debe ser válido'}), 400
    
    #valida el dominio
    if not email.endswith("gmail.com"):
        return jsonify({'message': 'Solo se permite correo electrónico con dominio @gmail.com'}), 400
    
    #si se proporciona la fecha de nacimiento se hara todo
    if fecha_nacimiento: 
        if not re.match(r'^(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$', fecha_nacimiento):
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
        return jsonify({'message': '¡Usuario registrado con exito!'}), 200
    else:
        return jsonify({'message': 'Error al registrar el usuario. Intente nuevamente'}), 500

#endpoint para login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'El email y la contraseña son requeridos'}), 400

    user = mongo.db.users.find_one({
        'email': email
    })

    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=str(user["_id"]), expires_delta=timedelta(days=31)) #expira el token en 31 dias
        return jsonify({
            'access_token': access_token,
        }), 200
    else:
        return jsonify({'message': 'Email y/o contraseña incorrectos. Intente nuevamente'}), 401
    
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
        return jsonify({'message': 'No se encontró el usuario'}), 404
    
#endpoint editar_perfil
@app.route('/editarPerfil', methods=['PUT'])
@jwt_required()
def editarPerfil():
    data = request.get_json()
    print(data)  # Verifica los datos que se reciben
    celular = data.get('celular')
    fecha_nacimiento = data.get('fecha_nacimiento')
    nombre = data.get('nombre')
    email = data.get('email')
    apellido_paterno = data.get('apellido_paterno')
    apellido_materno = data.get('apellido_materno')
    rol = data.get('rol')
    user_id = get_jwt_identity()

    user_id = ObjectId(user_id)
    
    # Verificamos si el usuario existe
    usuario = mongo.db.users.find_one({'_id': user_id})
    if not usuario:
        return jsonify({'message': 'No se encontró el usuario'}), 404

    # Diccionario vacío para almacenar los campos a actualizar
    datos_actualizados = {}

    # Validaciones de los campos opcionales
    if celular:
        if not re.match(r'^\d{10}$', celular):
            return jsonify({'message': 'Formato de celular invalido (10 dígitos)'}), 400
        datos_actualizados['celular'] = celular

    if fecha_nacimiento:
        if not re.match(r'^(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$', fecha_nacimiento):
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
        if email.endswith("gmail.com"):
            datos_actualizados['email'] = email
        else:
            return jsonify({'message': 'Solo se permite correo electrónico con dominio @gmail.com'}), 400

    if rol: 
        roles_validos = ['admin', 'user']
        if rol not in roles_validos:
            return jsonify({'message': f'Rol inválido. Roles válidos: {", ".join(roles_validos)}'}), 400
        datos_actualizados['rol'] = rol

    # Actualización en la base de datos
    result = mongo.db.users.update_one(
        {'_id': user_id},  # Filtro
        {'$set': datos_actualizados},  # Actualización
    )

    if result.modified_count > 0:
        return jsonify({'message': '¡Datos actualizados con éxito!'}), 200
    else:
        return jsonify({'message': 'No se recibieron datos para actualizar'}), 400

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
        return jsonify({'message': 'No se encontró el usuario'}), 404
    
    if not password:
        return jsonify({'message': 'Se requiere la contraseña para eliminar la cuenta'}), 400

    #verifica que la contraseña pasada por el usuario no sea diferente a la guardada en la base de datos 
    if not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'message': 'Contraseña incorrecta. Intenta nuevamente'}), 400

    result = mongo.db.users.delete_one({'_id': user_id})

    if result.deleted_count > 0:
        return jsonify({'message': '¡Cuenta eliminada con éxito!'}), 200
    else:
        return jsonify({'message': 'No se pudo eliminar la cuenta. Intente nuevamente'}), 400
    
#funcion para mandar el correo
#Message construye el correo
#primero va el subject (asunto)
#el destinatario debe estar en una lista
#y por ultimo el cuerpo
def send_email(destinatario, asunto, cuerpo, provider="gmail"): #se pone por default gmail 
    if provider == "gmail":
        msg = Message(subject=asunto, recipients=[destinatario], body=cuerpo, sender=app.config['MAIL_DEFAULT_SENDER']) #sender=app.config['MAIL_DEFAULT_SENDER'] especifica quien manda el correo
        mail_gmail.send(msg) #envia el correo

#genera un numero random de 3 digitos
def generar_codigo():
    return random.randint(100, 999)

#endpoint solicitar reestablecer contraseña
@app.route('/solicitarRestablecerContraseña', methods=['POST'])
def solicitarRestablecerContraseña():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Se requiere que proporcione su email'}), 400
    else:
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'message': 'Formato de correo electrónico invalido'}), 400
        if email.endswith("gmail.com"):
            pass #se sigue
        else:
            return jsonify({'message': 'Solo se permite correo electrónico con dominio @gmail.com'}), 400

    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'No se encontro un usuario con ese email'}), 404
    
    codigo = generar_codigo()
    timestamp = datetime.now(timezone.utc) #para checar que siga vigente
    
    #llama a la funcion que envia el correo
    send_email(email, 'Restablecer contraseña', f'Use este codigo de verificacion para restablecer su contraseña: {codigo}')

    result = mongo.db.codigos_passwords_users.insert_one({'email': email, 'codigo': codigo, 'codigo_timestamp': timestamp})

    if result.acknowledged:
        return jsonify({
            'message': 'Se ha enviado un correo con el codigo de verificacion para restablecer su contraseña'
        }), 200

#endpoint restablecer contraseña
@app.route('/restaurar_contraseña', methods=['POST'])
def restaurar_contraseña():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    codigo = data.get('codigo')

    if not email or not codigo or not password:
        return jsonify({'message': 'Email, codigo y contraseña nueva son requeridos'}), 400
    
    if email:
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'message': 'Formato de correo electrónico invalido'}), 400
        if email.endswith("gmail.com"):
            pass #se sigue
        else:
            return jsonify({'message': 'Solo se permite correo electrónico con dominio @gmail.com'}), 400
    
    user = mongo.db.codigos_passwords_users.find({'email': email})

    #convertir los resultados a una lista
    user_list = list(user)

    if not user_list:
        return jsonify({'message': 'No se encontró un usuario con ese email'}), 404
    
    codigo_valido = False
    #verificar si algún código coincide
    for documento in user_list:
       #verifica que el codigo que paso el usuario exista
       if str(codigo) == str(documento.get('codigo')) :
            codigo_valido = True
            codigo_timestamp = documento.get('codigo_timestamp')
            
            #verifica que codigo_timestamp tenga zona horaria (tzinfo tiene la info de si tiene o no)
            if codigo_timestamp.tzinfo is None:
                codigo_timestamp = codigo_timestamp.replace(tzinfo=timezone.utc)

            #calcula la direncia del tiempo actual y del tiempo en el que se creo el codigo para verificar que siga vigente
            tiempo_actual = datetime.now(timezone.utc)
            diferencia = tiempo_actual - codigo_timestamp

            #si la diferencia es mayor a 600 seg el codigo expira y lo elimina de la coleccion
            if diferencia.total_seconds() > 600: 
                return jsonify({'message': 'El código ha expirado'}), 400
            break #si encontramos el codigo se sale del bucle
       
    if not codigo_valido:
        return jsonify({'message': 'El código indicado no existe'}), 400
    

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    user = mongo.db.users.find_one({'email': email})
    if bcrypt.check_password_hash(user['password'], password):
        return jsonify({'message': 'Ingrese una contraseña que no sea la misma que la anterior'}), 400

    result = mongo.db.users.update_one(
        {'email': email}, 
        {'$set': {'password': hashed_password}} 
    )

    #si hubieron cambios se elimina el documento del usuario y del codigo de la coleccion
    if result.modified_count > 0:
        mongo.db.codigos_passwords_users.delete_many({'email': email})
        return jsonify({'message': '¡Contraseña restablecida con exito!'}), 200
    else:
        return jsonify({'message': 'Ocurrio un error al restablecer la contraseña. Intente nuevamente'}), 400

    
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
    #checa si hay algun archivo enviado con la clave 'archivo' y si lo hay lo guarda en file
    if 'archivo' not in request.files:
        return jsonify({'message': 'No hay ningun archivo'}), 400
    file = request.files['archivo']

    #crear el public_id para este video
    public_id = f'{user_id}/{categoria}/{file.filename}'

    try:
        #elimina cualquier video anterior con el mismo public_id antes de subir uno nuevo
        cloudinary.api.delete_resources_by_prefix(public_id, resource_type="video", type="upload", invalidate=True)

        #file es el archivo que quiero subir (obligatorio)
        #resource_type el tiop de archivo que le estoy mandando (obligatorio)
        #public_id es el identificador unico del archivo, este se usara para la url publica del video (secure_url) (no es obligaotrio pero sirve mucho si lo configuro yo)
        #asset_folder es para indicar el nombre del folder donde se guardara (no obligatorio)
        #overwrite es para que si ya existe un arhivo con ese public_id se sobreescriba (no obligatorio)
        #tags es para ponerle etiquetas (no obligaotrio)
        upload_result = cloudinary.uploader.upload(file, resource_type="video", public_id=public_id, asset_folder=categoria, overwrite=True, tags=[file.filename, categoria])

        return jsonify({
            'message': '¡Video guardado exitosamente!',
            "video": upload_result
        }), 200
    except Exception as e:
         return jsonify({'message': 'Error al subir el video', 'error': str(e)}), 500
    
    
#endpoint obtener todos los videos del usuario
@app.route('/mis_videos', methods=['GET'])
@jwt_required()
def mis_videos():
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontro un usuario'}), 404
    
    try:
        #obtener los recursos de un archivo de acuerdo a los parametros que le paso
        #type es especifica el tipo de recurso que deseas recuperar (en este caso subido por el usuario) (obligaotrio)
        #resource_type (obligatorio)
        #prefix sirve para filtrar por el inicio del public_id o sea aqui estoy filtrando para que solo se muestren los videos del usuario
        videos_usuario = cloudinary.api.resources(type='upload', resource_type='video', prefix=f"{user_id}")

        #obtener los videos (estan dentro de la clave resources) y si no hay manda una lista vacia
        videos = videos_usuario.get('resources', [])

        #obtener los secure_url, nombre y categoria de los archivos (estos 2 ultimos basandonos de la public_id)
        lista_videos = [] 
        for video in videos:
            lista_videos.append({
                'nombre_video': video['public_id'].split('/')[-1],
                'categoria_video': video['public_id'].split('/')[1],
                'secure_url': video['secure_url']
            }) 

        if not lista_videos:
            return jsonify({'message': 'No se encontraron videos asociados a este usuario. ¡Graba uno para empezar!'}), 404

        return jsonify({
            'videos':lista_videos
        })
    except Exception as e:
        return jsonify({'message': f'Error al obtener los videos: {str(e)}'}), 500
    

#endpoint obtener video por nombre del archivo
@app.route('/buscar_video/<categoria>/<nombre_video>', methods=['GET'])
@jwt_required()
def obtener_videos(categoria, nombre_video):
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontró un usuario'}), 404
    
    try:
        if categoria == "Todos":

            #search es para busquedas mas avanzadas (devuelve una LISTA de recursos)
            #expression son los parametros que se quienen buscar (obligatorio)
            #max_results dice que el numero maximo de resultados (no obligatorio)
            #execute hace que se ejecute la consulta (obligatorio)
            #busca un recurso cuyo 'public_id' comience con el `user_id` seguido de cualquier subcarpeta (`/*`) y cuyo nombre de archivo 'filename' coincida con el nombre proporcionado `nombre_video`
            busqueda_archivo = cloudinary.search.Search().expression(f"public_id:{user_id}/* AND filename:{nombre_video}").max_results(1).execute()

            recursos = busqueda_archivo.get('resources', [])
            
            if not recursos:
                return jsonify({"message": "No se pudo encontrar el video"}), 404
            
            #se obtiene el primer recurso encontrado en la búsqueda
            video_a_encontrar = recursos[0]
            return jsonify({
                "message": "¡Video encontrado exitosamente!",
                "nombre_video": video_a_encontrar['public_id'].split('/')[-1],
                'categoria_video': video_a_encontrar['public_id'].split('/')[1],
                'secure_url': video_a_encontrar['secure_url']
            }), 200
        else:
            video_public_id = f"{user_id}/{categoria}/{nombre_video}"
            video_a_encontrar = cloudinary.api.resource(video_public_id, resource_type = 'video')
            return jsonify({
                "message": "¡Video encontrado exitosamente!", 
                "nombre_video": video_a_encontrar['public_id'].split('/')[-1],
                'categoria_video': video_a_encontrar['public_id'].split('/')[1],
                'secure_url': video_a_encontrar['secure_url']
            }), 200

    except cloudinary.exceptions.NotFound:
        return jsonify({"message": "No se pudo encontrar el video"}), 404
    
    except Exception as e:
        return jsonify({"message": "Ocurrio un error al buscar el video", "details": str(e)}), 404


#endpoint buscar videos por categoria
@app.route('/buscar_por_categoria/<categoria>', methods=['GET'])
@jwt_required()
def buscar(categoria):
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)

    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontro un usuario'}), 404
    
    try:
        video_usuario_categoria = cloudinary.api.resources(type="upload", resource_type='video', prefix=f"{user_id}/{categoria}")
        videos = video_usuario_categoria.get('resources', [])

        lista_videos = []
        for video in videos:
            lista_videos.append({
                'nombre_video': video['public_id'].split('/')[-1],
                'categoria_video': video['public_id'].split('/')[1],
                'secure_url': video['secure_url']
            })

        if not lista_videos:
            return jsonify({'message': 'No se encontraron videos asociados a este usuario. ¡Graba uno para empezar!'}), 404
        
        return jsonify({
            'videos': lista_videos
        })
    except Exception as e:
        return jsonify({'message': f'Error al obtener los videos: {str(e)}'}), 500

#endpoint borrar video
@app.route('/borrar_video/<categoria>/<nombre_video>', methods=['DELETE'])
@jwt_required()
def borrar_video(categoria, nombre_video):
    user_id = get_jwt_identity()
    user_id = ObjectId(user_id)
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'message': 'No se encontro un usuario'}), 404
    
    video_public_id = f'{user_id}/{categoria}/{nombre_video}'

    try:
        cloudinary.api.delete_resources_by_prefix(video_public_id, resource_type="video", type="upload", invalidate=True)
        return jsonify({"message": "¡Video eliminado exitosamente!"}), 200
    except Exception as e:
        return jsonify({'message': f'Error al obtener los videos: {str(e)}'}), 500
    

#endpoint crear nombre propio abecededario y que se reproduzca en lenguaje de señas
@app.route('/crear_nombre_abecedario/<categoria>', methods=['POST'])
@jwt_required()
def crear_nombre_abecedario(categoria):
    try:
        data = request.get_json()
        nombre = data.get('nombre')
        user_id = get_jwt_identity()
        user_id = ObjectId(user_id)
        
        user = mongo.db.users.find_one({'_id': user_id})
        if not user:
            return jsonify({'message': 'No se encontro un usuario'}), 404
        
        if not nombre:
            return jsonify({'message': 'Se requiere que proporcione el nombre'}), 400

        #si el nombre termina con un espacio, elimina el utimo caracter con [:-1] y lo vuelve a asignar
        if nombre.endswith(" "):
            nombre = nombre[:-1]

        #si el nombre empieza con un espacio, elimina el primer caracter com [1:] y lo vuelve a asignar
        if nombre.startswith(" "):
            nombre = nombre[1:]

        if not re.match(r'^[a-zA-Z\s]+$', nombre):
            return jsonify({'message': 'El nombre debe contener solo caracteres alfabéticos y espacios'}), 400
        
        lista_videos = []
        try:
            for letra in nombre.replace(" ", ""):  #ignora los espacios en la busqueda
                video_public_id = f"{user_id}/Abecedario/{letra.upper()}" #convierte la letra a mayuscula porque asi estan guardados

                video_a_buscar = cloudinary.api.resource(video_public_id, type="upload", resource_type="video")
                lista_videos.append(video_a_buscar['secure_url']) #GUARDA LA SECURE_URL
        except cloudinary.exceptions.NotFound as e:
            return jsonify({'message': f'No existe un video con la letra: {letra}'}), 404

        #Descarga los videos
        videos = []
        for public_id in lista_videos:
            video_url = cloudinary.utils.cloudinary_url(public_id, resource_type='video')[0]
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.mp4')
            temp_file.close()
            os.system(f"curl -o {temp_file.name} {video_url}")

            # Abrir y agregar al listado de clips
            clip = VideoFileClip(temp_file.name)
            videos.append(clip)
        
        # Unir los clips
        final_clip = concatenate_videoclips(videos)
        
        # Guardar el video combinado en un archivo temporal
        temp_output = tempfile.NamedTemporaryFile(delete=False, suffix='.mp4')
        temp_output.close()
        final_clip.write_videofile(temp_output.name, codec="libx264")

        # Comprobar si ya existe un video con el nombre y eliminarlo si es necesario
        existing_video_public_id = f'{user_id}/Abecedario/{nombre.upper()}'
        cloudinary.api.delete_resources_by_prefix(existing_video_public_id, resource_type="video", type="upload")

        # Subir el video combinado a Cloudinary
        upload_result = cloudinary.uploader.upload(temp_output.name, resource_type="video", public_id=f'{user_id}/{categoria}/{nombre}', overwrite=True, asset_folder="Nombres")

        # Limpiar archivos temporales
        for clip in videos:
            clip.close()
        os.remove(temp_output.name)

        return jsonify({
            'message': '¡Nombre creado y guardado exitosamente',
            "secure_url": upload_result['secure_url']
        }), 200

    except Exception as e:
        return jsonify({'message': f'Error al obtener los videos: {str(e)}'}), 500
            


if __name__ == '__main__':
    app.run(debug=True)