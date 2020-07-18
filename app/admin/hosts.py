''' REST API for hosts '''
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

@admin.route('/hosts/<hostname>', methods=['PUT'])
@jwt_required
@requires_keyper_admin()
def update_host(hostname):
    ''' Update a Host '''
    app.logger.debug("Enter")
    dn = "cn=" + hostname + "," + app.config["LDAP_BASEHOST"]

    req = request.get_json()
    app.logger.debug(req)

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
        raise KeyperError(errors["ObjectDeleteError"].get("message"), errors["ObjectDeleteError"].get("status"))
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
    return jsonify("Deleted host: " + hostname)

def searchHosts(con, searchFilter):
    ''' Search for Hosts '''
    app.logger.debug("Enter")

    base_dn = app.config["LDAP_BASEHOST"]
    attrs = ['dn','cn','owner']

    try:
        result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,searchFilter, attrs)

        list = []

        for dn, entry in result:
            host = {}
            host["dn"] = dn
            owners = []

            if ("cn" in entry):
                for i in entry.get("cn"):
                    cn = i.decode()
                    host["cn"] = cn
            if ("owner" in entry):
                for owner in entry.get("owner"):
                    owners.append(owner.decode())
                    host["owners"] = owners

            list.append(host)
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return list


