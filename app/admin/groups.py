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


@admin.route('/groups', methods=['GET'])
@jwt_required
@requires_keyper_admin()
def get_groups():
    ''' Get all Groups '''
    app.logger.debug("Enter")
    con = operations.open_ldap_connection()
    result = searchGroups(con, '(objectClass=*)')
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
    result = searchGroups(con, '(&(objectClass=*)(cn=' + groupname + '))')
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
    attrs['objectClass'] = [b'groupOfNames',b'top']
    attrs["cn"] = [req["cn"].encode()]

    if ("members" in req):
        members = []
        for member in req.get("members"):
            members.append(member.encode())
        attrs["member"] = members

    dn = "cn=" + req["cn"] + "," + app.config["LDAP_BASEGROUPS"]

    try:
        con = operations.open_ldap_connection()
        ldif = modlist.addModlist(attrs)
        app.logger.debug("DN:" + dn)
        con.add_s(dn, ldif)
        operations.close_ldap_connection(con)
    except ldap.ALREADY_EXISTS:
        app.logger.error("LDAP Entry already exists:" + dn)
        raise KeyperError(errors["ObjectExistsError"].get("msg"), errors["ObjectExistsError"].get("status"))
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)
  
    app.logger.debug("Exit")
    return jsonify(req),201

@admin.route('/groups/<groupname>', methods=['PUT'])
@jwt_required
@requires_keyper_admin()
def update_group(groupname):
    ''' Update a Group '''
    app.logger.debug("Enter")
    dn = "cn=" + groupname + "," + app.config["LDAP_BASEGROUPS"]

    req = request.get_json()

    err = group_update_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    app.logger.debug(req)

    mod_list = []

    if ("members" in req):
        members = []
        for member in req.get("members"):
            members.append(member.encode())
        mod_list.append((ldap.MOD_REPLACE,"member",members))

    try:
        con = operations.open_ldap_connection()
        con.modify_s(dn,mod_list)
        operations.close_ldap_connection(con)
    except ldap.NO_SUCH_OBJECT:
        app.logger.error("Unable to delete. LDAP Entry not found:" + dn)
        raise KeyperError(errors["ObjectDeleteError"].get("msg"), errors["ObjectDeleteError"].get("status"))
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)


    app.logger.debug("Exit")
    return jsonify(req), 201

@admin.route('/groups/<groupname>', methods=['DELETE'])
@jwt_required
@requires_keyper_admin()
def delete_group(groupname):
    ''' Delete a Group '''
    app.logger.debug("Enter")
    dn = "cn=" + groupname + "," + app.config["LDAP_BASEGROUPS"]

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
    attrs = ['dn','cn','member']

    try:
        result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,searchFilter, attrs)

        list = []

        for dn, entry in result:
            group = {}
            group["dn"] = dn
            members = []

            if ("cn" in entry):
                for i in entry.get("cn"):
                    cn = i.decode()
                    group["cn"] = cn
            if ("member" in entry):
                for member in entry.get("member"):
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
    members = fields.List(fields.Str(validate=Length(max=200)), required=False)

    class Meta:
        fields = ("cn", "members")

class GroupUpdateSchema(Schema):
    members = fields.List(fields.Str(validate=Length(max=200)), required=True)

group_create_schema = GroupCreateSchema()
group_update_schema = GroupUpdateSchema()
