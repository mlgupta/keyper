''' REST API for users '''
import sys
import os
import json
import ldap
import ldap.modlist as modlist
from time import strftime,gmtime
from flask import request, jsonify
from flask import current_app as app
from flask_jwt_extended import jwt_required
from marshmallow import fields, Schema
from marshmallow.validate import Length, Email
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
    err = user_create_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("message"), errors["SchemaValidationError"].get("status"))

    app.logger.debug(req)

    attrs = {}
    attrs['objectClass'] = [b'inetOrgPerson',b'top',b'ldapPublicKey',b'pwdPolicy']
    attrs["cn"] = [req["cn"].encode()]
    attrs["uid"] = [req["cn"].encode()]
    attrs["sn"] = [req["sn"].encode()]
    attrs["pwdAttribute"] = b'userPassword'


    if ("givenName" in req):
        attrs["givenName"] = [req["givenName"].encode()]

    if ("displayName" in req):
        attrs["displayName"] = [req["displayName"].encode()]

    if ("mail" in req):
        attrs["mail"] = [req["mail"].encode()]

    if ("accountLocked" in req):
        accountLocked = req["accountLocked"]
        if accountLocked is True:
            dt_utc = get_generalized_time()
            attrs["pwdAccountLockedTime"] = dt_utc.encode()

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
        app.logger.debug("User created: " + dn)

        if ("memberOfs" in req):
            for memberOf in req.get("memberOfs"):
                mod_list = []
                mod_list.append((ldap.MOD_ADD,"member",[dn.encode()]))
                app.logger.debug("Adding user: " + dn + " to group: " + memberOf)
                con.modify_s(memberOf,mod_list)

        list = []
        list = search_users(con,'(&(objectClass=*)(cn=' + req["cn"] + '))')

        operations.close_ldap_connection(con)
    except ldap.ALREADY_EXISTS:
        app.logger.error("LDAP Entry already exists:" + dn)
        raise KeyperError(errors["ObjectExistsError"].get("message"), errors["ObjectExistsError"].get("status"))
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)
  
    app.logger.debug("Exit")
    return jsonify(list),201

@admin.route('/users/<username>', methods=['PUT'])
@jwt_required
def update_user(username):
    ''' Update a user '''
    app.logger.debug("Enter")
    dn = "cn=" + username + "," + app.config["LDAP_BASEUSER"]

    req = request.get_json()
    app.logger.debug(req)

    err = user_update_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        raise KeyperError(errors["SchemaValidationError"].get("message"), errors["SchemaValidationError"].get("status"))

    mod_list = []

    if ("sn" in req):
        mod_list.append((ldap.MOD_REPLACE,"sn",[req["sn"].encode()]))

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
        if ("accountLocked" in req):
            user = {}
            user = search_users(con,'(&(objectClass=*)(cn=' + username + '))').pop()
            
            accountLocked = req["accountLocked"]
            dt_utc = get_generalized_time()

            if "pwdAccountLockedTime" in user:
                app.logger.debug("User is Locked: " + username)
                if accountLocked is True:
                    app.logger.debug("Re Locking user: " + username)
                    mod_list.append((ldap.MOD_REPLACE,"pwdAccountLockedTime",[dt_utc.encode()]))
                else:
                    app.logger.debug("Unlocking user: " + username)
                    mod_list.append((ldap.MOD_DELETE,"pwdAccountLockedTime",None))
            else:
                app.logger.debug("User is Not Locked: " + username)
                if accountLocked is True:
                    app.logger.debug("Locking user: " + username)
                    mod_list.append((ldap.MOD_ADD,"pwdAccountLockedTime",[dt_utc.encode()]))

        if (len(mod_list) > 0):        
            con.modify_s(dn,mod_list)

        if ("memberOfs" in req):
            if not("accountLocked" in req):
                user = {}
                user = search_users(con,'(&(objectClass=*)(cn=' + username + '))').pop()

            memberOfs_req = set(req["memberOfs"])
            memberOfs_ldap = {}
            
            if ("memberOfs" in user):
                memberOfs_ldap = set(user["memberOfs"])

            for memberOf in memberOfs_req.difference(memberOfs_ldap):
                mod_list = []
                mod_list.append((ldap.MOD_ADD,"member",[dn.encode()]))
                app.logger.debug("Adding user: " + dn + " to group: " + memberOf)
                con.modify_s(memberOf,mod_list)

            for memberOf in memberOfs_ldap.difference(memberOfs_req):
                mod_list = []
                mod_list.append((ldap.MOD_DELETE,"member",[dn.encode()]))
                app.logger.debug("Deleting user: " + dn + " from group: " + memberOf)
                con.modify_s(memberOf,mod_list)

        list = []
        list = search_users(con,'(&(objectClass=*)(cn=' + username + '))')
        
        operations.close_ldap_connection(con)
    except ldap.NO_SUCH_OBJECT:
        app.logger.error("Unable to delete. LDAP Entry not found:" + dn)
        raise KeyperError(errors["ObjectDeleteError"].get("message"), errors["ObjectDeleteError"].get("status"))
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)


    app.logger.debug("Exit")
    return jsonify(list), 201

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
    attrs = ['dn','cn','uid','givenName','sn','displayName','sshPublicKey','mail','memberOf','pwdAccountLockedTime']

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
            if ("pwdAccountLockedTime" in entry):
                user["accountLocked"] = True
                for i in entry.get("pwdAccountLockedTime"):
                    pwdAccountLockedTime = i.decode()
                    user["pwdAccountLockedTime"] = pwdAccountLockedTime
            else:
                user["accountLocked"] = False

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

def get_generalized_time():
    ''' Return generized time as string '''
    app.logger.debug("Enter")
    dt_utc = strftime("%Y%m%d%H%M%SZ",gmtime())

    app.logger.debug("Exit")
    return dt_utc

class UserCreateSchema(Schema):
    cn = fields.Str(required=True, validate=Length(max=100))
    userPassword = fields.Str(required=True, validate=Length(max=100))
    givenName = fields.Str(required=True, validate=Length(max=100))
    sn = fields.Str(required=True, validate=Length(max=100))
    displayName = fields.Str(required=False, validate=Length(max=100))
    mail = fields.Email(required=False, validate=Length(max=100))
    accountLocked = fields.Bool(required=False)
    sshPublicKeys = fields.List(fields.Str(validate=Length(max=2000)), required=False)
    memberOfs = fields.List(fields.Str(validate=Length(max=200)), required=False)

    class Meta:
        fields = ("cn", "userPassword", "givenName", "sn", "displayName", "mail", "accountLocked", "sshPublicKeys", "memberOfs")

class UserUpdateSchema(Schema):
    userPassword = fields.Str(required=False, validate=Length(max=100))
    givenName = fields.Str(required=False, validate=Length(max=100))
    sn = fields.Str(required=False, validate=Length(max=100))
    displayName = fields.Str(required=False, validate=Length(max=100))
    mail = fields.Email(required=False, validate=Length(max=100))
    accountLocked = fields.Bool(required=False)
    sshPublicKeys = fields.List(fields.Str(validate=Length(max=2000)), required=False)
    memberOfs = fields.List(fields.Str(validate=Length(max=200)), required=False)

    class Meta:
        fields = ("userPassword", "givenName", "sn", "displayName", "mail", "accountLocked", "sshPublicKeys", "memberOfs")

user_create_schema = UserCreateSchema()
user_update_schema = UserUpdateSchema()
