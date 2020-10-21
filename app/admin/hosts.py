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
''' REST API for hosts '''
import sys
import json
import ldap
import ldap.modlist as modlist
from flask import request, jsonify
from flask import current_app as app
from flask_jwt_extended import jwt_required
from marshmallow import fields, Schema
from marshmallow.validate import Length, Range, OneOf
from . import admin
from ..resources.errors import KeyperError, errors
from ..utils import operations
from ..utils.sshca import SSHCA
from ..utils.extensions import requires_keyper_admin
from ldapDefn import *

@admin.route('/hosts', methods=['GET'])
@jwt_required
@requires_keyper_admin()
def get_hosts():
    ''' Get all Hosts '''
    app.logger.debug("Enter")
    con = operations.open_ldap_connection()
    result = searchHosts(con, '(' + LDAP_ATTR_OBJECTCLASS + '=*)')
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
    result = searchHosts(con, '(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + hostname + '))')
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
    attrs[LDAP_ATTR_OBJECTCLASS] = LDAP_OBJECTCLASS_HOST
    attrs[LDAP_ATTR_CN] = [req["cn"].encode()]

    if ("owners" in req):
        owners = []
        for owner in req.get("owners"):
            owners.append(owner.encode())
        attrs[LDAP_ATTR_OWNER] = owners

    if ("description" in req):
        attrs[LDAP_ATTR_DESCRIPTION] = [req.get("description").encode()]

    if ("principal" in req):
        principal = []
        for princ in req.get("principal"):
            principal.append(princ.encode())
        attrs[LDAP_ATTR_PRINCIPAL] = principal

    if ("duration" in req):
        duration = {}
        duration["duration"] = req.get("duration")
        duration["durationUnit"] = req.get("durationUnit")
        attrs[LDAP_ATTR_OPTION] = [json.dumps(duration).encode()]

    if ("sshPublicCerts" in req):
        keyid = 100
        keytype = 1
        sshPublicCerts = []
        sshca = SSHCA()
        principal_list = req.get("principal")
        principal_list = [princ.strip() for princ in principal_list]
        principal_list = [princ for princ in principal_list if princ]
        principal  = ','.join(principal_list)
        date_expire = operations.duration_to_date_expire(req.get("duration"), req.get("durationUnit"))

        for sshPublicCert in req.get("sshPublicCerts"):
            key = sshPublicCert.get("key")
            cert = sshca.sign_host_key(hostkey=key, duration=date_expire, hostname=req["cn"], principal_list=principal)
            sshPublicCert["keyid"] = keyid
            sshPublicCert["keytype"] = keytype
            sshPublicCert["cert"] = cert
            sshPublicCert["dateExpire"] = date_expire
            keyid += 1
            sshPublicCerts.append(json.dumps(sshPublicCert).encode())

        attrs[LDAP_ATTR_SSHPUBLICKEY] = sshPublicCerts

    dn = LDAP_ATTR_CN + "=" + req["cn"] + "," + app.config["LDAP_BASEHOST"]
    group_dn = LDAP_ATTR_CN + "=" + req["cn"] + "," + app.config["LDAP_BASEGROUPS"]
    allhost_group_dn = app.config["LDAP_ALL_HOST_GROUP"]

    try:
        # Create Host
        con = operations.open_ldap_connection()
        ldif = modlist.addModlist(attrs)
        app.logger.debug("Adding Host with DN:" + dn)
        con.add_s(dn, ldif)

        # Create Group
        attrs={}
        attrs[LDAP_ATTR_OBJECTCLASS] = LDAP_OBJECTCLASS_GROUP
        attrs[LDAP_ATTR_CN] = [req["cn"].encode()]
        attrs[LDAP_ATTR_MEMBER] = [dn.encode()]
        description = req["cn"] + " Autocreated Group"
        attrs[LDAP_ATTR_DESCRIPTION] = [description.encode()]

        app.logger.debug("Adding Group with DN:" + group_dn)

        ldif_group = modlist.addModlist(attrs)
        con.add_s(group_dn, ldif_group)

        #Adding host to AllHost Group
        mod_list = []
        mod_list.append((ldap.MOD_ADD, LDAP_ATTR_MEMBER, dn.encode()))
        con.modify_s(allhost_group_dn,mod_list)

        hosts = []
        hosts = searchHosts(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + req["cn"] + '))')

        operations.close_ldap_connection(con)
    except ldap.ALREADY_EXISTS:
        app.logger.error("LDAP Entry already exists:" + dn)
        raise KeyperError(errors["ObjectExistsError"].get("msg"), errors["ObjectExistsError"].get("status"))
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)
  
    app.logger.debug("Exit")
    return jsonify(hosts),201

@admin.route('/hosts/<hostname>', methods=['PUT'])
@jwt_required
@requires_keyper_admin()
def update_host(hostname):
    ''' Update a Host '''
    app.logger.debug("Enter")
    dn = LDAP_ATTR_CN + "=" + hostname + "," + app.config["LDAP_BASEHOST"]

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
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_OWNER,owners))

    if ("description" in req):
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_DESCRIPTION,[req.get("description").encode()]))

    if ("duration" in req):
        option = {}
        option["duration"] = req.get("duration")
        option["durationUnit"] = req.get("durationUnit")
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_OPTION,json.dumps(option).encode()))

    if ("principal" in req):
        principal = []
        for princ in req.get("principal"):
            principal.append(princ.encode())
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_PRINCIPAL,principal))

    try:
        con = operations.open_ldap_connection()

        if ("sshPublicCerts" in req):
            sshPublicCerts = []
            sshca = SSHCA()
            hosts = []
            hosts = searchHosts(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + hostname + '))')
            host = hosts[0]

            app.logger.debug("duration: " + host.get("duration"))
            app.logger.debug("durationUnit: " + host.get("durationUnit"))
            date_expire = operations.duration_to_date_expire(host.get("duration"), host.get("durationUnit"))
            principal_list = host.get("principal")
            principal  = ','.join(principal_list)

            keyid = 100
            keytype = 1
            if ("sshPublicCerts" in host):
                sshPublicCerts = host.get("sshPublicCerts")
                keyid = max(list(map(lambda key: key['keyid'], sshPublicCerts))) + 1

            for sshPublicCert in req.get("sshPublicCerts"):
                if ("keyid" in sshPublicCert):
                    # Delete a cert
                    sshPublicCerts = list(filter(lambda key: key['keyid'] != sshPublicCert['keyid'], sshPublicCerts))
                else: 
                    # Create a cert  
                    sshPublicCert['keyid'] = keyid
                    sshPublicCert['keytype'] = keytype
                    key = sshPublicCert.get("key")
                    cert = sshca.sign_host_key(hostkey=key, duration=date_expire, hostname=hostname, principal_list=principal)
                    sshPublicCert["cert"] = cert
                    sshPublicCert["dateExpire"] = date_expire
                    keyid += 1
                    
                    sshPublicCerts.append(sshPublicCert)
            
            if(len(sshPublicCerts) > 0):
                sshPublicCerts = list(map(lambda key: json.dumps(key).encode(), sshPublicCerts))
                mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_SSHPUBLICKEY,sshPublicCerts))
            else:
                if ("sshPublicCerts" in host):
                    mod_list.append((ldap.MOD_DELETE,LDAP_ATTR_SSHPUBLICKEY,None))

        con.modify_s(dn,mod_list)
        
        hosts = []
        hosts = searchHosts(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + hostname + '))')

        operations.close_ldap_connection(con)
    except ldap.NO_SUCH_OBJECT:
        app.logger.error("Unable to delete. LDAP Entry not found:" + dn)
        raise KeyperError(errors["ObjectDeleteError"].get("msg"), errors["ObjectDeleteError"].get("status"))
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")
    return jsonify(hosts), 201

@admin.route('/hosts/<hostname>', methods=['DELETE'])
@jwt_required
@requires_keyper_admin()
def delete_host(hostname):
    ''' Delete a Host '''
    app.logger.debug("Enter")
    dn = LDAP_ATTR_CN + "=" + hostname + "," + app.config["LDAP_BASEHOST"]
    group_dn = LDAP_ATTR_CN + "=" + hostname + "," + app.config["LDAP_BASEGROUPS"]

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
    attrs = [LDAP_ATTR_DN,LDAP_ATTR_CN,LDAP_ATTR_DESCRIPTION,LDAP_ATTR_OWNER,LDAP_ATTR_MEMBEROF,LDAP_ATTR_SSHPUBLICKEY, LDAP_ATTR_PRINCIPAL, LDAP_ATTR_OPTION]

    try:
        result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,searchFilter, attrs)

        hosts = []

        for dn, entry in result:
            host = {}
            host["dn"] = dn
            owners = []
            sshPublicCerts = []
            principal = []
            memberOfs = []

            if (LDAP_ATTR_CN in entry):
                for i in entry.get(LDAP_ATTR_CN):
                    cn = i.decode()
                    host["cn"] = cn
            
            if (LDAP_ATTR_DESCRIPTION in entry):
                for i in entry.get(LDAP_ATTR_DESCRIPTION):
                    description = i.decode()
                    host["description"] = description
            
            if (LDAP_ATTR_OWNER in entry):
                for owner in entry.get(LDAP_ATTR_OWNER):
                    owners.append(owner.decode())
                    host["owners"] = owners
            
            if (LDAP_ATTR_MEMBEROF in entry):
                for memberOf in entry.get(LDAP_ATTR_MEMBEROF):
                    memberOfs.append(memberOf.decode())
                host["memberOfs"] = memberOfs
                
            if (LDAP_ATTR_SSHPUBLICKEY in entry):
                for key in entry.get(LDAP_ATTR_SSHPUBLICKEY):
                    sshPublicCert = {}
                    app.logger.debug(key.decode())
                    sshPublicCert = json.loads(key.decode())
                    sshPublicCerts.append(sshPublicCert)
                host["sshPublicCerts"] = sshPublicCerts

            if (LDAP_ATTR_PRINCIPAL in entry):
                for princ in entry.get(LDAP_ATTR_PRINCIPAL):
                    principal.append(princ.decode())
                host["principal"] = principal

            if (LDAP_ATTR_OPTION in entry):
                option = json.loads(entry.get(LDAP_ATTR_OPTION)[0].decode())
                host["duration"] = option.get("duration")
                host["durationUnit"] = option.get("durationUnit")

            hosts.append(host)
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return hosts

class sshPublicCertSchema(Schema):
    keyid = fields.Int(required=False)
    keytype = fields.Int(required=False)
    name = fields.Str(required=True, validate=Length(max=100))
    key = fields.Str(required=True, validate=Length(max=3000))
    fingerprint = fields.Str(required=True, validate=Length(max=100))
    dateExpire = fields.DateTime(required=False)
    cert = fields.Str(required=False,validate=Length(max=5000))

    class Meta:
        datetimeformat = '%Y%m%d%H%M%S'
        fields = ("keyid", "keytype", "name", "key", "fingerprint", "cert", "dateExpire")

class HostCreateSchema(Schema):
    cn = fields.Str(required=True, validate=Length(max=100))
    description = fields.Str(required=False, validate=Length(max=1000), allow_none=True)
    owners = fields.List(fields.Str(required=False, validate=Length(max=200)))
    principal = fields.List(fields.Str(required=True, validate=Length(max=100)))
    duration = fields.Int(required=True, validate=Range(min=1, max=500))
    durationUnit = fields.Str(required=True, validate=OneOf(['Hours', 'Days', 'Weeks']))
    sshPublicCerts = fields.List(fields.Nested(sshPublicCertSchema), required=False)

    class Meta:
        fields = ("cn", "owners", "description", "sshPublicCerts", "principal", "duration", "durationUnit")

class HostUpdateSchema(Schema):
    description = fields.Str(validate=Length(max=1000))
    owners = fields.List(fields.Str(validate=Length(max=200)))
    principal = fields.List(fields.Str(required=False, validate=Length(max=100)))
    duration = fields.Int(required=False, validate=Range(min=1, max=500))
    durationUnit = fields.Str(required=False, validate=OneOf(['Hours', 'Days', 'Weeks']))
    sshPublicCerts = fields.List(fields.Nested(sshPublicCertSchema), required=False)

    class Meta:
        fields = ("owners", "description", "sshPublicCerts", "principal", "duration", "durationUnit")

host_create_schema = HostCreateSchema()
host_update_schema = HostUpdateSchema()

