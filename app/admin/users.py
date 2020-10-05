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
''' REST API for users '''
import sys
import os
import json
import ldap
import ldap.modlist as modlist
from time import strftime, gmtime
from flask import request, jsonify
from flask import current_app as app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt_claims
from marshmallow import fields, Schema
from marshmallow.validate import Length, Email
from . import admin
from ..resources.errors import KeyperError, errors
from ..utils import operations
from ..utils.extensions import requires_keyper_admin
from ldapDefn import *

@admin.route('/users', methods=['GET'])
@jwt_required
@requires_keyper_admin()
def get_users():
    ''' List All Users '''
    app.logger.debug("Enter")
    con = operations.open_ldap_connection()
    result = search_users(con, '(' + LDAP_ATTR_OBJECTCLASS + '=*)')
    operations.close_ldap_connection(con)

    app.logger.debug("Exit")

    return jsonify(result)

@admin.route('/users/<username>', methods=['GET'])
@jwt_required
def get_user(username):
    ''' List a User '''
    app.logger.debug("Enter")
    con = operations.open_ldap_connection()
    result = search_users(con, '(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + username + '))')
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
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    app.logger.debug(req)

    attrs = {}
    attrs[LDAP_ATTR_OBJECTCLASS] = LDAP_OBJECTCLASS_USER
    attrs[LDAP_ATTR_CN] = [req["cn"].encode()]
    attrs[LDAP_ATTR_UID] = [req["cn"].encode()]
    attrs[LDAP_ATTR_SN] = [req["sn"].encode()]
    app.logger.debug("here")
    attrs[LDAP_ATTR_PWDATTRIBUTE] = bytes(LDAP_ATTR_USERPASSWORD, encoding='utf-8')

    app.logger.debug(" after here")

    if ("givenName" in req):
        attrs[LDAP_ATTR_GIVENNAME] = [req["givenName"].encode()]

    if ("displayName" in req):
        attrs[LDAP_ATTR_DISPLAYNAME] = [req["displayName"].encode()]

    if ("mail" in req):
        attrs[LDAP_ATTR_MAIL] = [req["mail"].encode()]

    if ("accountLocked" in req):
        accountLocked = req["accountLocked"]
        if accountLocked is True:
            dt_utc = get_generalized_time()
            attrs[LDAP_ATTR_PWDACCOUNTLOCKEDTIME] = dt_utc.encode()

    if ("userPassword" in req):
        attrs[LDAP_ATTR_USERPASSWORD] = [req["userPassword"].encode()]

    if ("sshPublicKeys" in req):
        sshPublicKeys = []
        for sshPublicKey in req.get("sshPublicKeys"):
            app.logger.debug(json.dumps(sshPublicKey))
            sshPublicKeys.append(json.dumps(sshPublicKey).encode())
        attrs[LDAP_ATTR_SSHPUBLICKEY] = sshPublicKeys

    dn = LDAP_ATTR_CN + "=" + req["cn"] + "," + app.config["LDAP_BASEUSER"] 

    try:
        con = operations.open_ldap_connection()
        ldif = modlist.addModlist(attrs)
        app.logger.debug("DN:" + dn)
        con.add_s(dn, ldif)
        app.logger.debug("User created: " + dn)

        if ("memberOfs" in req):
            for memberOf in req.get("memberOfs"):
                mod_list = []
                mod_list.append((ldap.MOD_ADD,LDAP_ATTR_MEMBER,[dn.encode()]))
                app.logger.debug("Adding user: " + dn + " to group: " + memberOf)
                con.modify_s(memberOf,mod_list)

        list = []
        list = search_users(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + req["cn"] + '))')

        operations.close_ldap_connection(con)
    except ldap.ALREADY_EXISTS:
        app.logger.error("LDAP Entry already exists:" + dn)
        raise KeyperError(errors["ObjectExistsError"].get("msg"), errors["ObjectExistsError"].get("status"))
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
    dn = LDAP_ATTR_CN + "=" + username + "," + app.config["LDAP_BASEUSER"]

    req = request.get_json()
    app.logger.debug(req)

    err = user_update_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    mod_list = []

    if ("sn" in req):
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_SN,[req["sn"].encode()]))

    if ("givenName" in req):
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_GIVENNAME,[req["givenName"].encode()]))

    if ("displayName" in req):
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_DISPLAYNAME,[req["displayName"].encode()]))

    if ("mail" in req):
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_MAIL,[req["mail"].encode()]))
    
    if ("userPassword" in req):
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_USERPASSWORD,[req["userPassword"].encode()]))

    if ("sshPublicKeys" in req):
        sshPublicKeys = []
        for sshPublicKey in req.get("sshPublicKeys"):
            sshPublicKeys.append(json.dumps(sshPublicKey).encode())
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_SSHPUBLICKEY,sshPublicKeys))

    try:
        con = operations.open_ldap_connection()

        KEYPER_ADMIN = app.config["JWT_ADMIN_ROLE"]
        user_claims = get_jwt_claims()
        app.logger.debug("user_claims: " + user_claims)

        if KEYPER_ADMIN in user_claims:
            if ("accountLocked" in req):
                user = {}
                user = search_users(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + username + '))').pop()
            
                accountLocked = req["accountLocked"]
                dt_utc = get_generalized_time()

                if LDAP_ATTR_PWDACCOUNTLOCKEDTIME in user:
                    app.logger.debug("User is Locked: " + username)
                    if accountLocked is True:
                        app.logger.debug("Re Locking user: " + username)
                        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_PWDACCOUNTLOCKEDTIME,[dt_utc.encode()]))
                    else:
                        app.logger.debug("Unlocking user: " + username)
                        mod_list.append((ldap.MOD_DELETE,LDAP_ATTR_PWDACCOUNTLOCKEDTIME,None))
                else:
                    app.logger.debug("User is Not Locked: " + username)
                    if accountLocked is True:
                        app.logger.debug("Locking user: " + username)
                        mod_list.append((ldap.MOD_ADD,LDAP_ATTR_PWDACCOUNTLOCKEDTIME,[dt_utc.encode()]))

        if (len(mod_list) > 0):        
            con.modify_s(dn,mod_list)

        if KEYPER_ADMIN in user_claims:
            if ("memberOfs" in req):
                if not("accountLocked" in req):
                    user = {}
                    user = search_users(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + username + '))').pop()

                memberOfs_req = set(req["memberOfs"])
                memberOfs_ldap = {}
            
                if ("memberOfs" in user):
                    memberOfs_ldap = set(user["memberOfs"])

                for memberOf in memberOfs_req.difference(memberOfs_ldap):
                    mod_list = []
                    mod_list.append((ldap.MOD_ADD,LDAP_ATTR_MEMBER,[dn.encode()]))
                    app.logger.debug("Adding user: " + dn + " to group: " + memberOf)
                    con.modify_s(memberOf,mod_list)

                for memberOf in memberOfs_ldap.difference(memberOfs_req):
                    mod_list = []
                    mod_list.append((ldap.MOD_DELETE,LDAP_ATTR_MEMBER,[dn.encode()]))
                    app.logger.debug("Deleting user: " + dn + " from group: " + memberOf)
                    con.modify_s(memberOf,mod_list)

        list = []
        list = search_users(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + username + '))')
        
        operations.close_ldap_connection(con)
    except ldap.NO_SUCH_OBJECT:
        app.logger.error("Unable to delete. LDAP Entry not found:" + dn)
        raise KeyperError(errors["ObjectDeleteError"].get("msg"), errors["ObjectDeleteError"].get("status"))
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
    dn = LDAP_ATTR_CN + "=" + username + "," + app.config["LDAP_BASEUSER"]
    
    if (username.lower() in app.config["LDAP_PROTECTED_USERS"]):
        app.logger.error("Protected resource. Delete for user " + username + " is not allowed")
        raise KeyperError(errors["ObjectProtectedError"].get("msg"), errors["ObjectProtectedError"].get("status"))

    try:
        con = operations.open_ldap_connection()
        con.delete_s(dn)
        operations.close_ldap_connection(con)
    except ldap.NO_SUCH_OBJECT:
        app.logger.error("Unable to delete. LDAP Entry not found:" + dn)
        raise KeyperError(errors["ObjectDeleteError"].get("msg"), errors["ObjectDeleteError"].get("status"))
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
    attrs = [LDAP_ATTR_DN,LDAP_ATTR_CN,LDAP_ATTR_UID,LDAP_ATTR_GIVENNAME,LDAP_ATTR_SN,LDAP_ATTR_DISPLAYNAME,LDAP_ATTR_SSHPUBLICKEY,LDAP_ATTR_MAIL,LDAP_ATTR_MEMBEROF,LDAP_ATTR_PWDACCOUNTLOCKEDTIME]

    try:
        result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,searchFilter, attrs)

        list = []

        for dn, entry in result:
            user = {}
            user["dn"] = dn
            sshPublicKeys = []
            memberOfs = []

            if (LDAP_ATTR_CN in entry):
                for i in entry.get(LDAP_ATTR_CN):
                    cn = i.decode()
                    user["cn"] = cn
            if (LDAP_ATTR_UID in entry):
                for i in entry.get(LDAP_ATTR_UID):
                    uid = i.decode()
                    user["uid"] = uid
            if (LDAP_ATTR_SN in entry):
                for i in entry.get(LDAP_ATTR_SN):
                    sn = i.decode()
                    user["sn"] = sn
            if (LDAP_ATTR_GIVENNAME in entry):
                for i in entry.get(LDAP_ATTR_GIVENNAME):
                    givenName = i.decode()
                    user["givenName"] = givenName
            if (LDAP_ATTR_DISPLAYNAME in entry):
                for i in entry.get(LDAP_ATTR_DISPLAYNAME):
                    displayName = i.decode()
                    user["displayName"] = displayName
            if (LDAP_ATTR_MAIL in entry):
                for i in entry.get(LDAP_ATTR_MAIL):
                    mail = i.decode()
                    user["mail"] = mail
            if (LDAP_ATTR_PWDACCOUNTLOCKEDTIME in entry):
                user["accountLocked"] = True
                for i in entry.get(LDAP_ATTR_PWDACCOUNTLOCKEDTIME):
                    pwdAccountLockedTime = i.decode()
                    user["pwdAccountLockedTime"] = pwdAccountLockedTime
            else:
                user["accountLocked"] = False

            if (LDAP_ATTR_MEMBEROF in entry):
                for memberOf in entry.get(LDAP_ATTR_MEMBEROF):
                    memberOfs.append(memberOf.decode())
                user["memberOfs"] = memberOfs
            if (LDAP_ATTR_SSHPUBLICKEY in entry):
                for key in entry.get(LDAP_ATTR_SSHPUBLICKEY):
                    sshPublicKey = {}
                    app.logger.debug(key.decode())
                    sshPublicKey = json.loads(key.decode())
                    sshPublicKeys.append(sshPublicKey)
                user["sshPublicKeys"] = sshPublicKeys

            list.append(user)
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return list

def cn_from_dn(memberOf):
    ''' Return cn from DN '''
    app.logger.debug("Enter")
    cn = memberOf.split(",")[0].split("=")[1]
    app.logger.debug("Exit")
    return cn

def get_generalized_time():
    ''' Return generized time as string '''
    app.logger.debug("Enter")
    dt_utc = strftime("%Y%m%d%H%M%SZ",gmtime())

    app.logger.debug("Exit")
    return dt_utc

class sshPublicKeySchema(Schema):
    name = fields.Str(required=True, validate=Length(max=100))
    key = fields.Str(required=True, validate=Length(max=3000))
    fingerprint = fields.Str(required=True, validate=Length(max=100))
    dateExpire = fields.Date(required=True)
    hostGroups = fields.List(fields.Str(validate=Length(max=200)))

    class Meta:
        dateformat = '%Y%m%d'
        fields = ("name", "key", "fingerprint", "dateExpire", "hostGroups")

class UserCreateSchema(Schema):
    cn = fields.Str(required=True, validate=Length(max=100))
    userPassword = fields.Str(required=True, validate=Length(max=100))
    confirmPassword = fields.Str(required=True, validate=Length(max=100))
    givenName = fields.Str(required=True, validate=Length(max=100))
    sn = fields.Str(required=True, validate=Length(max=100))
    displayName = fields.Str(required=False, validate=Length(max=100))
    mail = fields.Email(required=False, validate=Length(max=100))
    accountLocked = fields.Bool(required=False)
    sshPublicKeys = fields.List(fields.Nested(sshPublicKeySchema), required=False)
    memberOfs = fields.List(fields.Str(validate=Length(max=200)), required=False)

    class Meta:
        fields = ("cn", "userPassword", "confirmPassword", "givenName", "sn", "displayName", "mail", "accountLocked", "sshPublicKeys", "memberOfs")

class UserUpdateSchema(Schema):
    userPassword = fields.Str(required=False, validate=Length(max=100))
    confirmPassword = fields.Str(required=False, validate=Length(max=100))
    givenName = fields.Str(required=False, validate=Length(max=100))
    sn = fields.Str(required=False, validate=Length(max=100))
    displayName = fields.Str(required=False, validate=Length(max=100))
    mail = fields.Email(required=False, validate=Length(max=100))
    accountLocked = fields.Bool(required=False)
    sshPublicKeys = fields.List(fields.Nested(sshPublicKeySchema), required=False)
    memberOfs = fields.List(fields.Str(validate=Length(max=200)), required=False)

    class Meta:
        fields = ("userPassword", "confirmPassword", "givenName", "sn", "displayName", "mail", "accountLocked", "sshPublicKeys", "memberOfs")

user_create_schema = UserCreateSchema()
user_update_schema = UserUpdateSchema()
