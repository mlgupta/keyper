''' Authentication module '''
import sys
import ldap
import ldap.modlist as modlist
from flask import request, jsonify
from flask import current_app as app
from flask_jwt_extended import create_access_token, create_refresh_token, get_raw_jwt, jwt_required, jwt_refresh_token_required
from . import admin
from ..resources.errors import KeyperError, errors
from ..utils import operations
from ..utils.extensions import *

@admin.route('/login', methods=['POST'])
def login():
    ''' Login '''
    app.logger.debug("Enter")

    username = request.json.get('username', None)
    password = request.json.get('password', None)

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
        return_code = 401
        return_message = "{msg: Bad Username or Password}"
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    if (user_authenticated):
        try:
            con = operations.open_ldap_connection()

            base_dn = app.config["LDAP_BASEUSER"]
            attrs = ['dn','cn','memberOf']
            searchFilter = '(&(objectClass=*)(cn=' + username + '))'

            app.logger.debug("Getting User role")

            result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,searchFilter, attrs)

            for dn, entry in result:
                memberOfs = []
                user_role = 'keyper_user'

                if ("memberOf" in entry):
                    for memberOf in entry.get("memberOf"):
                        if 'keyperadmin' in memberOf.decode().lower():
                            user_role = 'keyper_admin'

            operations.close_ldap_connection(con)

            role = "{role: " + user_role + "}"
            app.logger.debug("role:" + role)
            app.logger.debug("Generating JWT Tokens")

            access_token = create_access_token(identity=username, user_claims=role)
            refresh_token = create_refresh_token(identity=username, user_claims=role)

            return_message = {
                'access_token': access_token,
                'refresh_token': refresh_token
            }
            return_code = 200
        except ldap.NO_SUCH_OBJECT:
            app.logger.error("Unable to delete. LDAP Entry not found:" + dn)
            raise KeyperError(errors["ObjectDeleteError"].get("message"), errors["ObjectDeleteError"].get("status"))
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
    current_user = get_jwt_identity
    user_claims = get_jwt_claims
    access_token = create_access_token(identity=username, user_claims=role)
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