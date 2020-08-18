''' Authentication module '''
import sys
import json
import ldap
from flask import request, jsonify
from flask import current_app as app
from flask_jwt_extended import create_access_token, create_refresh_token, get_raw_jwt, jwt_required
from flask_jwt_extended import jwt_refresh_token_required, get_jwt_identity, get_jwt_claims
from marshmallow import fields, Schema
from marshmallow.validate import Length
from . import admin
from ..resources.errors import KeyperError, errors
from ..utils import operations
from ..utils.extensions import *
from ..admin.users import search_users

@admin.route('/login', methods=['POST'])
def login():
    ''' Login '''
    app.logger.debug("Enter")

    req = request.get_json()

    err = login_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    username = req['username']
    password = req['password']

    app.logger.debug("username/password:" + username + "/" + password)

    return_code = 200

    try:
        user_authenticated = False
        con = operations.open_ldap_connection_no_bind()
        
        dn = "cn=" + username + "," + app.config["LDAP_BASEUSER"] 
        app.logger.debug("dn:" + dn)

        con.simple_bind_s(dn, password)
        user_authenticated = True
        app.logger.debug("User Authenticated")
    except ldap.INVALID_CREDENTIALS:
        app.logger.error("Authentication failure. Invalid Credentials for user:" + username)
        raise KeyperError(errors["UnauthorizedError"].get("msg"), errors["UnauthorizedError"].get("status"))

    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    if (user_authenticated):
        try:
            con = operations.open_ldap_connection()

            searchFilter = '(&(objectClass=*)(cn=' + username + '))'

            list = search_users(con, searchFilter)
            app.logger.debug("list length: " + str(len(list)))
            operations.close_ldap_connection(con)

            user = list.pop()

            app.logger.debug("Getting User role")
            user_role = app.config["JWT_USER_ROLE"]
            if ("memberOfs" in user):
                memberOfs = user["memberOfs"]
                for memberOf in memberOfs:
                    app.logger.debug("memberOf: " + memberOf)
                    if 'keyperadmins' in memberOf.lower():
                        user_role = app.config["JWT_ADMIN_ROLE"]
                
            app.logger.debug("User role: " + user_role)

            role = "{role: " + user_role + "}"
            app.logger.debug("role:" + role)
            app.logger.debug("Generating JWT Tokens")

            access_token = create_access_token(identity=username, user_claims=role)
            refresh_token = create_refresh_token(identity=username, user_claims=role)

            user["access_token"] = access_token
            user["refresh_token"] = refresh_token

            return_message = user
            return_code = 200
        except ldap.NO_SUCH_OBJECT:
            app.logger.error("Unable to delete. LDAP Entry not found:" + dn)
            raise KeyperError(errors["ObjectDeleteError"].get("msg"), errors["ObjectDeleteError"].get("status"))
        except ldap.LDAPError:
            exctype, value = sys.exc_info()[:2]
            app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
            raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return jsonify(return_message), return_code

@admin.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    ''' Refreshes JWT token using refresh token '''
    app.logger.debug("Enter")
    current_user = get_jwt_identity()
    user_claims = get_jwt_claims()
    app.logger.debug("username: " + current_user)
    app.logger.debug("user_claims: " + user_claims)
    access_token = create_access_token(identity=current_user, user_claims=user_claims)
    return_code = 200
    return_message = { 
        'access_token': access_token
    }
    app.logger.debug("Exit")
    return jsonify(return_message), return_code

@admin.route('/logout', methods=['DELETE'])
@jwt_required
def logout():
    ''' Logout '''
    app.logger.debug("Enter")

    jti = get_raw_jwt()['jti']
    blacklist.add(jti)

    app.logger.debug("Exit")

    return jsonify({"msg": "Successfully logged out"}), 200

@admin.route('/check_jwt_token', methods=['GET'])
@jwt_required
def check_token_freshness():
    ''' Checks JWT Token Freshness '''
    app.logger.debug("Enter")

    app.logger.debug("Exit")

    return jsonify({"msg": "Token Valid"}), 200

class LoginSchema(Schema):
    username = fields.Str(required=True, validate=Length(max=100))
    password = fields.Str(required=True, validate=Length(max=100))

    class Meta:
        fields = ("username", "password")

login_schema = LoginSchema()