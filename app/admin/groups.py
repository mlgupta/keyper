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
''' REST API for groups '''
import sys
import json
import ldap
import ldap.modlist as modlist
from flask import request, jsonify
from flask import current_app as app
from flask_jwt_extended import jwt_required
from marshmallow import fields, Schema
from marshmallow.validate import Length
from . import admin
from ..resources.errors import KeyperError, errors
from ..utils import operations
from ..utils.extensions import requires_keyper_admin
from ldapDefn import *


@admin.route('/groups', methods=['GET'])
@jwt_required
@requires_keyper_admin()
def get_groups():
    ''' Get all Groups '''
    app.logger.debug("Enter")
    con = operations.open_ldap_connection()
    result = searchGroups(con, '(' + LDAP_ATTR_OBJECTCLASS + '=*)')
    operations.close_ldap_connection(con)

    app.logger.debug("Exit")

    return jsonify(result)

@admin.route('/groups/<groupname>', methods=['GET'])
@jwt_required
@requires_keyper_admin()
def get_group(groupname):
    ''' Get a Group '''
    app.logger.debug("Enter")
    con = operations.open_ldap_connection()
    result = searchGroups(con, '(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + groupname + '))')
    operations.close_ldap_connection(con)
    app.logger.debug("Exit")

    return jsonify(result)

@admin.route('/groups', methods=['POST'])
@jwt_required
@requires_keyper_admin()
def create_group():
    ''' Create a Group '''
    app.logger.debug("Enter")
    req = request.get_json()

    err = group_create_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    app.logger.debug(req)

    attrs = {}
    attrs[LDAP_ATTR_OBJECTCLASS] = LDAP_OBJECTCLASS_GROUP
    attrs[LDAP_ATTR_CN] = [req["cn"].encode()]

    if ("description" in req):
        attrs[LDAP_ATTR_DESCRIPTION] = [req["description"].encode()]

    if ("members" in req):
        members = []
        for member in req.get("members"):
            members.append(member.encode())
        attrs[LDAP_ATTR_MEMBER] = members

    dn = LDAP_ATTR_CN + "=" + req["cn"] + "," + app.config["LDAP_BASEGROUPS"]

    try:
        con = operations.open_ldap_connection()
        ldif = modlist.addModlist(attrs)
        app.logger.debug("DN:" + dn)
        con.add_s(dn, ldif)

        list = []
        list = searchGroups(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + req["cn"] + '))')

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

@admin.route('/groups/<groupname>', methods=['PUT'])
@jwt_required
@requires_keyper_admin()
def update_group(groupname):
    ''' Update a Group '''
    app.logger.debug("Enter")
    dn = LDAP_ATTR_CN + "=" + groupname + "," + app.config["LDAP_BASEGROUPS"]

    req = request.get_json()

    err = group_update_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    app.logger.debug(req)

    mod_list = []

    if ("description" in req):
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_DESCRIPTION,[req.get("description").encode()]))

    if ("members" in req):
        members = []
        for member in req.get("members"):
            members.append(member.encode())
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_MEMBER,members))

    try:
        con = operations.open_ldap_connection()
        con.modify_s(dn,mod_list)

        list = []
        list = searchGroups(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + groupname + '))')

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

@admin.route('/groups/<groupname>', methods=['DELETE'])
@jwt_required
@requires_keyper_admin()
def delete_group(groupname):
    ''' Delete a Group '''
    app.logger.debug("Enter")
    dn = LDAP_ATTR_CN + "=" + groupname + "," + app.config["LDAP_BASEGROUPS"]

    if (groupname.lower() in app.config["LDAP_PROTECTED_GROUPS"]):
        app.logger.error("Protected resource. Delete for group " + groupname + " is not allowed")
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
    return jsonify("Deleted group: " + groupname)

def searchGroups(con, searchFilter):
    ''' Search Groups '''
    app.logger.debug("Enter")

    base_dn = app.config["LDAP_BASEGROUPS"]
    attrs = [LDAP_ATTR_DN,LDAP_ATTR_CN, LDAP_ATTR_DESCRIPTION, LDAP_ATTR_MEMBER]

    try:
        result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,searchFilter, attrs)

        list = []

        for dn, entry in result:
            group = {}
            group["dn"] = dn
            members = []

            if (LDAP_ATTR_CN in entry):
                for i in entry.get(LDAP_ATTR_CN):
                    cn = i.decode()
                    group["cn"] = cn
            if (LDAP_ATTR_DESCRIPTION in entry):
                for i in entry.get(LDAP_ATTR_DESCRIPTION):
                    description = i.decode()
                    group["description"] = description
            if (LDAP_ATTR_MEMBER in entry):
                for member in entry.get(LDAP_ATTR_MEMBER):
                    members.append(member.decode())
                    group["members"] = members

            list.append(group)
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return list

class GroupCreateSchema(Schema):
    cn = fields.Str(required=True, validate=Length(max=100))
    description = fields.Str(required=False, validate=Length(max=1000))
    members = fields.List(fields.Str(validate=Length(max=200)), required=False)

    class Meta:
        fields = ("cn", "members", "description")

class GroupUpdateSchema(Schema):
    members = fields.List(fields.Str(validate=Length(max=200)))
    description = fields.Str(validate=Length(max=1000))

    class Meta:
        fields = ("members", "description")

group_create_schema = GroupCreateSchema()
group_update_schema = GroupUpdateSchema()
