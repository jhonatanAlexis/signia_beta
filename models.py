from flask_pymongo import PyMongo

mongo = PyMongo()

def init_db(app):
    #inicializa MongoDB
    mongo.init_app(app)