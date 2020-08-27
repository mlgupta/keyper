#############################################################################
#                       Confidentiality Information                         #
#                                                                           #
# This module is the confidential and proprietary information of            #
# DBSentry Corp.; it is not to be copied, reproduced, or transmitted in any #
# form, by any means, in whole or in part, nor is it to be used for any     #
# purpose other than that for which it is expressly provided without the    #
# written permission of DBSentry Corp.                                      #
#                                                                           #
# Copyright (c) 2020-2021 DBSentry Corp.  All Rights Reserved.              #
#                                                                           #
#############################################################################
''' So that jwt can be used by different Blueprints '''
import json
from functools import wraps
from flask_jwt_extended import JWTManager, get_jwt_identity, get_jwt_claims
from flask import current_app as app
from flask import request, jsonify
from flask_marshmallow import Marshmallow
from ..resources.errors import KeyperError, errors
from .flask_logs import LogSetup


jwt = JWTManager()
logs = LogSetup()
ma = Marshmallow()

blacklist = set()

@jwt.expired_token_loader
def expired_token(expired_token):
    ''' This gets called for expired tokens '''
    app.logger.debug("Enter")
    app.logger.debug("Exit")
    return jsonify({"msg": "Token Expired"}), 401



@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    ''' Check for blacklisted token '''
    app.logger.debug("Enter")

    jti = decrypted_token['jti']
    app.logger.debug("Exit")

    return jti in blacklist

@jwt.claims_verification_loader
def user_load_callback(user_claims):
    ''' Validate User's role is allowed to access a resource '''
    app.logger.debug("Enter")

    return_flag = True
    
    KEYPER_ADMIN = app.config["JWT_ADMIN_ROLE"]
    user = get_jwt_identity()
    user_claims = get_jwt_claims()
    app.logger.debug("user_claims: " + user_claims)

    if not KEYPER_ADMIN in user_claims:
        allowed_url = "/users/" + user
        url = request.path
        app.logger.debug("url: " + url)

        if url != allowed_url:
            return_flag = False

    app.logger.debug("Exit")

    return return_flag

def requires_keyper_admin():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            KEYPER_ADMIN = 'keyper_admin'
            user_claims = get_jwt_claims()
            app.logger.debug("user_claims: " + user_claims)

            if not KEYPER_ADMIN in user_claims:
                app.logger.debug("user not authorized")
                raise KeyperError(errors["UnauthorizedAccessError"].get("msg"), errors["UnauthorizedAccessError"].get("status"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator