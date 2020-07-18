''' REST API for users '''
import sys
import ldap
import ldap.modlist as modlist
from flask import request, jsonify
from flask import current_app as app
from flask_jwt_extended import jwt_required
from . import admin
from ..resources.errors import KeyperError, errors
from ..utils import operations
from ..utils.extensions import requires_keyper_admin

@admin.route('/users', methods=['GET'])
@jwt_required
@requires_keyper_admin()
def get_users():
    ''' List All Users '''
    app.logger.debug("Enter")
    con = operations.open_ldap_connection()
    result = search_users(con, '(objectClass=*)')
    operations.close_ldap_connection(con)

    app.logger.debug("Exit")

    return jsonify(result)

@admin.route('/users/<username>', methods=['GET'])
@jwt_required
def get_user(username):
    ''' List a User '''
    app.logger.debug("Enter")
    con = operations.open_ldap_connection()
    result = search_users(con, '(&(objectClass=*)(cn=' + username + '))')
    operations.close_ldap_connection(con)
    app.logger.debug("Exit")

    return jsonify(result)

@admin.route('/users', methods=['POST'])
@jwt_required
@requires_keyper_admin()
def create_user():
    ''' Create a User '''
    app.logger.debug("Enter")
    req = request.get_json()
    app.logger.debug(req)

    attrs = {}
    attrs['objectClass'] = [b'inetOrgPerson',b'top',b'ldapPublicKey']
    attrs["cn"] = [req["cn"].encode()]
    attrs["uid"] = [req["cn"].encode()]
    attrs["sn"] = [req["sn"].encode()]

    if ("givenName" in req):
        attrs["givenName"] = [req["givenName"].encode()]

    if ("displayName" in req):
        attrs["displayName"] = [req["displayName"].encode()]

    if ("mail" in req):
        attrs["mail"] = [req["mail"].encode()]

    if ("userPassword" in req):
        attrs["userPassword"] = [req["userPassword"].encode()]

    if ("sshPublicKeys" in req):
        sshPublicKeys = []
        for sshPublicKey in req.get("sshPublicKeys"):
            sshPublicKeys.append(sshPublicKey.encode())
        attrs["sshPublicKey"] = sshPublicKeys

    dn = "cn=" + req["cn"] + "," + app.config["LDAP_BASEUSER"] 

    try:
        con = operations.open_ldap_connection()
        ldif = modlist.addModlist(attrs)
        app.logger.debug("DN:" + dn)
        con.add_s(dn, ldif)
        operations.close_ldap_connection(con)
    except ldap.ALREADY_EXISTS:
        app.logger.error("LDAP Entry already exists:" + dn)
        raise KeyperError(errors["ObjectExistsError"].get("message"), errors["ObjectExistsError"].get("status"))
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)
  
    app.logger.debug("Exit")
    return jsonify(req),201

@admin.route('/users/<username>', methods=['PUT'])
@jwt_required
def update_user(username):
    ''' Update a user '''
    app.logger.debug("Enter")
    dn = "cn=" + username + "," + app.config["LDAP_BASEUSER"]

    req = request.get_json()
    app.logger.debug(req)

    mod_list = []

    if ("sn" in req):
        mod_list.append((
            ldap.MOD_REPLACE,"sn",[req["sn"].encode()]))

    if ("giveName" in req):
        mod_list.append((ldap.MOD_REPLACE,"giveName",[req["giveName"].encode()]))

    if ("displayName" in req):
        mod_list.append((ldap.MOD_REPLACE,"displayName",[req["displayName"].encode()]))

    if ("mail" in req):
        mod_list.append((ldap.MOD_REPLACE,"mail",[req["mail"].encode()]))
    
    if ("userPassword" in req):
        mod_list.append((ldap.MOD_REPLACE,"userPassword",[req["userPassword"].encode()]))

    if ("sshPublicKeys" in req):
        sshPublicKeys = []
        for sshPublicKey in req.get("sshPublicKeys"):
            sshPublicKeys.append(sshPublicKey.encode())
        mod_list.append((ldap.MOD_REPLACE,"sshPublicKey",sshPublicKeys))

    try:
        con = operations.open_ldap_connection()
        con.modify_s(dn,mod_list)
        operations.close_ldap_connection(con)
    except ldap.NO_SUCH_OBJECT:
        app.logger.error("Unable to delete. LDAP Entry not found:" + dn)
        raise KeyperError(errors["ObjectDeleteError"].get("message"), errors["ObjectDeleteError"].get("status"))
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)


    app.logger.debug("Exit")
    return jsonify(req), 201

@admin.route('/users/<username>', methods=['DELETE'])
@jwt_required
@requires_keyper_admin()
def delete_user(username):
    ''' Delete a User '''
    app.logger.debug("Enter")
    dn = "cn=" + username + "," + app.config["LDAP_BASEUSER"]

    try:
        con = operations.open_ldap_connection()
        con.delete_s(dn)
        operations.close_ldap_connection(con)
    except ldap.NO_SUCH_OBJECT:
        app.logger.error("Unable to delete. LDAP Entry not found:" + dn)
        raise KeyperError(errors["ObjectDeleteError"].get("message"), errors["ObjectDeleteError"].get("status"))
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")
    return jsonify("Deleted User: " + username)

def search_users(con, searchFilter):
    ''' Search for users '''
    app.logger.debug("Enter")

    base_dn = app.config["LDAP_BASEUSER"]
    attrs = ['dn','cn','uid','givenName','sn','displayName','sshPublicKey','mail','memberOf']

    try:
        result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,searchFilter, attrs)

        list = []

        for dn, entry in result:
            user = {}
            user["dn"] = dn
            sshPublicKeys = []
            memberOfs = []

            if ("cn" in entry):
                for i in entry.get("cn"):
                    cn = i.decode()
                    user["cn"] = cn
            if ("uid" in entry):
                for i in entry.get("uid"):
                    uid = i.decode()
                    user["uid"] = uid
            if ("sn" in entry):
                for i in entry.get("sn"):
                    sn = i.decode()
                    user["sn"] = sn
            if ("givenName" in entry):
                for i in entry.get("givenName"):
                    givenName = i.decode()
                    user["givenName"] = givenName
            if ("displayName" in entry):
                for i in entry.get("displayName"):
                    displayName = i.decode()
                    user["displayName"] = displayName
            if ("mail" in entry):
                for i in entry.get("mail"):
                    mail = i.decode()
                    user["mail"] = mail
            if ("memberOf" in entry):
                for memberOf in entry.get("memberOf"):
                    memberOfs.append(memberOf.decode())
                    user["memberOfs"] = memberOfs
            if ("sshPublicKey" in entry):
                for sshPublicKey in entry.get("sshPublicKey"):
                    sshPublicKeys.append(sshPublicKey.decode())
                    user["sshPublicKeys"] = sshPublicKeys

            list.append(user)
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return list


