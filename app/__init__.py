''' Keyper API app '''
import logging
import json
from os import environ
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from .resources.errors import KeyperError
from .utils.extensions import jwt, logs, ma
from config import config

def create_app():
    ''' Create app '''
    app = Flask(__name__)

    flask_config = "config." + config.get(environ.get('FLASK_CONFIG'), 'DevelopmentConfig')

    #app.config.from_object("config.DevelopmentConfig")

    app.config.from_object(flask_config)

    logs.init_app(app)

    app.logger.debug("flask_config: " + flask_config)

    jwt.init_app(app)

    ma.init_app(app)

    CORS(app)

    from .admin import admin as admin_blueprint
    app.register_blueprint(admin_blueprint)

    from .public import public as public_blueprint
    app.register_blueprint(public_blueprint)

    @app.errorhandler(KeyperError)
    def handle_keyper_error(error):
        ''' Error Handler '''
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response

    return app


