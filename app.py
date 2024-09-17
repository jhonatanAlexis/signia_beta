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

if __name__ == '__main__':
    app.run(debug=True)