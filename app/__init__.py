''' Keyper API app '''
import logging
import json
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from .resources.errors import KeyperError
from .utils.extensions import jwt, logs, ma

def create_app():
    ''' Create app '''
    app = Flask(__name__)
    app.config.from_object("config.DevelopmentConfig")
    #log_level = logging.DEBUG
    #app.logger.setLevel(log_level)

    logs.init_app(app)

    jwt.init_app(app)

    ma.init_app(app)

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

