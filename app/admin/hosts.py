''' REST API for hosts '''
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


@admin.route('/hosts', methods=['GET'])
@jwt_required
@requires_keyper_admin()
def get_hosts():
    ''' Get all Hosts '''
    app.logger.debug("Enter")
    con = operations.open_ldap_connection()
    result = searchHosts(con, '(objectClass=*)')
    operations.close_ldap_connection(con)

    app.logger.debug("Exit")

    return jsonify(result)

@admin.route('/hosts/<hostname>', methods=['GET'])
@jwt_required
@requires_keyper_admin()
def get_host(hostname):
    ''' Get a Host '''
    app.logger.debug("Enter")
    con = operations.open_ldap_connection()
    result = searchHosts(con, '(&(objectClass=*)(cn=' + hostname + '))')
    operations.close_ldap_connection(con)
    app.logger.debug("Exit")

    return jsonify(result)

@admin.route('/hosts', methods=['POST'])
@jwt_required
@requires_keyper_admin()
def create_host():
    ''' Create a Host '''
    app.logger.debug("Enter")
    req = request.get_json()

    err = host_create_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    app.logger.debug(req)

    attrs = {}
    attrs['objectClass'] = [b'device',b'top']
    attrs["cn"] = [req["cn"].encode()]

    if ("owners" in req):
        owners = []
        for owner in req.get("owners"):
            owners.append(owner.encode())
        attrs["owner"] = owners

    dn = "cn=" + req["cn"] + "," + app.config["LDAP_BASEHOST"]
    group_dn = "cn=" + req["cn"] + "," + app.config["LDAP_BASEGROUPS"]

    try:
        con = operations.open_ldap_connection()
        ldif = modlist.addModlist(attrs)
        app.logger.debug("Adding User with DN:" + dn)
        con.add_s(dn, ldif)

        attrs={}
        attrs['objectClass'] = [b'groupOfNames',b'top']
        attrs["cn"] = [req["cn"].encode()]
        attrs["member"] = [dn.encode()]
        app.logger.debug("Adding Group with DN:" + group_dn)

        ldif_group = modlist.addModlist(attrs)
        con.add_s(group_dn, ldif_group)

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

@admin.route('/hosts/<hostname>', methods=['PUT'])
@jwt_required
@requires_keyper_admin()
def update_host(hostname):
    ''' Update a Host '''
    app.logger.debug("Enter")
    dn = "cn=" + hostname + "," + app.config["LDAP_BASEHOST"]

    req = request.get_json()
    app.logger.debug(req)

    err = host_update_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    mod_list = []

    if ("owners" in req):
        owners = []
        for owner in req.get("owners"):
            owners.append(owner.encode())
        mod_list.append((ldap.MOD_REPLACE,"owner",owners))

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

@admin.route('/hosts/<hostname>', methods=['DELETE'])
@jwt_required
@requires_keyper_admin()
def delete_host(hostname):
    ''' Delete a Host '''
    app.logger.debug("Enter")
    dn = "cn=" + hostname + "," + app.config["LDAP_BASEHOST"]
    group_dn = "cn=" + hostname + "," + app.config["LDAP_BASEGROUPS"]

    try:
        con = operations.open_ldap_connection()
        app.logger.debug("Deleting Hosts: " + dn)
        con.delete_s(dn)
        app.logger.debug("Deleting Group: " + group_dn)
        con.delete_s(group_dn)
        operations.close_ldap_connection(con)
    except ldap.NO_SUCH_OBJECT:
        app.logger.error("Unable to delete. LDAP Entry not found:" + dn)
        raise KeyperError(errors["ObjectDeleteError"].get("msg"), errors["ObjectDeleteError"].get("status"))
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")
    return jsonify("Deleted host: " + hostname)

def searchHosts(con, searchFilter):
    ''' Search for Hosts '''
    app.logger.debug("Enter")

    base_dn = app.config["LDAP_BASEHOST"]
    attrs = ['dn','cn','owner','memberOf']

    try:
        result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,searchFilter, attrs)

        list = []

        for dn, entry in result:
            host = {}
            host["dn"] = dn
            owners = []
            memberOfs = []

            if ("cn" in entry):
                for i in entry.get("cn"):
                    cn = i.decode()
                    host["cn"] = cn
            if ("owner" in entry):
                for owner in entry.get("owner"):
                    owners.append(owner.decode())
                    host["owners"] = owners
            if ("memberOf" in entry):
                for memberOf in entry.get("memberOf"):
                    memberOfs.append(memberOf.decode())
                host["memberOfs"] = memberOfs

            list.append(host)
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return list

class HostCreateSchema(Schema):
    cn = fields.Str(required=True, validate=Length(max=100))
    owners = fields.List(fields.Str(validate=Length(max=200)), required=False)

    class Meta:
        fields = ("cn", "owners")

class HostUpdateSchema(Schema):
    owners = fields.List(fields.Str(validate=Length(max=200)), required=True)

host_create_schema = HostCreateSchema()
host_update_schema = HostUpdateSchema()

