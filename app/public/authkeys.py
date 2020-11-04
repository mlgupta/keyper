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
''' API to get user's SSH Public Keys '''
import sys
import json
import ldap
from flask import request, Response, send_from_directory
from flask import current_app as app
from marshmallow import fields, Schema
from marshmallow.validate import Length
from datetime import datetime
from . import public
from ..resources.errors import KeyperError, errors
from ..utils import operations
from ..utils.sshca import SSHCA
from ..utils.sshkrl import SSHKRL
from ..admin.users import search_users, cn_from_dn
from ..admin.hosts import searchHosts
from ldapDefn import *

@public.route('/authkeys', methods=['GET','POST'])
def get_authkeys():
    ''' Get SSH Public Keys '''
    app.logger.debug("Enter")

    req = request.values

    err = authkey_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    username = request.values.get('username')
    host = request.values.get('host')
    fingerprint = request.values.get('fingerprint')

    app.logger.debug("username/host: " + username + "/" + host)

    sshkrl = SSHKRL()

    sshPublicKeys = []
    result = ""

    if (fingerprint is None):
        app.logger.debug("fingerprint is None")
    else:
        if (":" not in fingerprint):
            app.logger.debug("Invalid fingerprint")
            return Response(result, mimetype='text/plain')

    if (sshkrl.is_key_revoked(fingerprint)):
        app.logger.info("Key in KRL")
        return Response(result, mimetype='text/plain')

    con = operations.open_ldap_connection()

    users = []
    users = search_users(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(|(' + LDAP_ATTR_CN + '=' + username + ')(' + LDAP_ATTR_PRINCIPAL + '=' + username + ')))')

    for user in users:
        if not (LDAP_ATTR_CN in user):
            raise KeyperError(errors["UnauthorizedAccessError"].get("msg"), errors["UnauthorizedAccessError"].get("status"))

        return_groups = isUserAuthorized(con, user, host)
        if (len(return_groups) > 0):
            sshPublicKeys += getSSHPublicKeys(con, user, host, fingerprint, return_groups)
        else:
            app.logger.debug("User not allowed to access host: " + user[LDAP_ATTR_CN] + "/" + host)

    result = '\n'.join(sshPublicKeys)

    operations.close_ldap_connection(con)
    
    app.logger.debug("Exit")
    return Response(result, mimetype='text/plain')

@public.route('/authprinc', methods=['GET','POST'])
def get_authprinc():
    ''' Get SSH Public Keys '''
    app.logger.debug("Enter")

    req = request.values

    err = authprinc_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    username = request.values.get('username')
    host = request.values.get('host')
    fingerprint = request.values.get('fingerprint')
    cert_serial = request.values.get('serial')

    app.logger.debug("username/host/fingerprint/serial: " + username + "/" + host + "/" + fingerprint + "/" + str(cert_serial))

    sshPublicCerts = []
    result = ""

    sshkrl = SSHKRL()

    if (sshkrl.is_cert_revoked(cert_serial)):
        app.logger.info("Cert in KRL")
        return Response(result, mimetype='text/plain')

    con = operations.open_ldap_connection()

    users = []
    users = search_users(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(|(' + LDAP_ATTR_CN + '=' + username + ')(' + LDAP_ATTR_PRINCIPAL + '=' + username + ')))')
    tnow = datetime.utcnow()

    for user in users:
        return_groups = isUserAuthorized(con, user, host)
        if (len(return_groups) > 0):
            if ("sshPublicCerts" in user):
                for sshPublicCert in user.get("sshPublicCerts"):
                    dateExpire = datetime.strptime(sshPublicCert["dateExpire"],"%Y%m%d%H%M%S")
                    hostGroups = set(map(lambda grp: grp.lower(), sshPublicCert["hostGroups"]))
                    keyFP = sshPublicCert["fingerprint"]

                    if (tnow <= dateExpire):
                        if(fingerprint == keyFP):
                            if (len(return_groups.intersection(hostGroups)) > 0):
                                result = username + "\n"
                                break
                        else:
                            app.logger.debug("Cert Fingerprint does not match")
                    else:
                        app.logger.debug("Cert expired")
                if (result != ""):
                    break
            else: 
                app.logger.debug("No SSH Public Cert in User: " + user[LDAP_ATTR_CN])
        else:
            app.logger.debug("User not allowed to access host: " + user[LDAP_ATTR_CN] + "/" + host)

    operations.close_ldap_connection(con)
    
    app.logger.debug("Exit")
    return Response(result, mimetype='text/plain')

@public.route('/hostcert', methods=['GET'])
def get_hostcert():
    ''' Get Cert for a host '''
    app.logger.debug("Enter")

    req = request.values

    err = host_cert_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    hostname = request.values.get('hostname')
    keyid = request.values.get('keyid')
    fingerprint = request.values.get('fingerprint')

    app.logger.debug("hostname: " + hostname)

    sshPublicCerts = []
    result = ""

    con = operations.open_ldap_connection()

    host = {}
    hosts = []
    hosts = searchHosts(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + hostname + '))')
    tnow = datetime.utcnow()

    if (len(hosts) > 0):
        host = hosts.pop()

    if not (LDAP_ATTR_CN in host):
        raise KeyperError(errors["UnauthorizedAccessError"].get("msg"), errors["UnauthorizedAccessError"].get("status"))

    if ("sshPublicCerts" in host):
        sshPublicCerts = host.get("sshPublicCerts")
    else:
        raise KeyperError(errors["SSHPublicCertNotExistError"].get("msg"), errors["SSHPublicCertNotExistError"].get("status"))

    if(len(sshPublicCerts) == 0):
        raise KeyperError(errors["SSHPublicCertNotExistError"].get("msg"), errors["SSHPublicCertNotExistError"].get("status"))

    for sshPublicCert in sshPublicCerts:
        cert = sshPublicCert.get("cert")
        dateExpire = datetime.strptime(sshPublicCert["dateExpire"],"%Y%m%d%H%M%S")
        keyFP = sshPublicCert["fingerprint"]
        keyID = int(sshPublicCert["keyid"])

        app.logger.debug("Cert Extracted")

        if (dateExpire > tnow):
            app.logger.debug("Cert is valid")
            if (((keyid is None) or (int(keyid) == keyID)) and ((fingerprint is None) or (fingerprint == keyFP))):
                result = result + cert + "\n"
            else:
                app.logger.debug("Fingerprints or keyid don't match. keyID/fingerprint: " + str(keyID) + "/" + keyFP)
        else:
            app.logger.debug("Cert Expired")

    operations.close_ldap_connection(con)
    
    app.logger.debug("Exit")
    return Response(result, mimetype='text/plain')

@public.route('/hostca', methods=['GET', 'POST'])
def get_hostca():
    ''' Get Hosts CA Public Key '''
    app.logger.debug("Enter")

    ssh_ca_host_public_key = app.config["SSH_CA_DIR"] + "/" + app.config["SSH_CA_HOST_KEY"] + ".pub"

    ca_key = ""

    with open(ssh_ca_host_public_key, 'r') as ca_file:
        ca_key = ca_file.read()
        ca_file.close()
    
    app.logger.debug("Exit")
    return Response(ca_key, mimetype='text/plain')

@public.route('/userca', methods=['GET', 'POST'])
def get_userca():
    ''' Get User CA Public Key '''
    app.logger.debug("Enter")

    ssh_ca_user_public_key = app.config["SSH_CA_DIR"] + "/" + app.config["SSH_CA_USER_KEY"] + ".pub"

    ca_key = ""

    with open(ssh_ca_user_public_key, 'r') as ca_file:
        ca_key = ca_file.read()
        ca_file.close()
    
    app.logger.debug("Exit")
    return Response(ca_key, mimetype='text/plain')

@public.route('/krlca', methods=['GET', 'POST'])
def get_krlca():
    ''' Get KRL File '''
    app.logger.debug("Enter")

    try:
        return send_from_directory(directory=app.config["SSH_CA_DIR"], filename=app.config["SSH_CA_KRL_FILE"], as_attachment=True)
    except FileNotFoundError:
        app.logger.error("KRL FIle Not Found Exception")
        raise KeyperError("KRL File Not Found Exception",404)

@public.route('/usercert', methods=['GET'])
def get_usercert():
    ''' Get Cert for a user '''
    app.logger.debug("Enter")

    req = request.values

    err = user_cert_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    username = request.values.get('username')
    keyid = request.values.get('keyid')
    fingerprint = request.values.get('fingerprint')

    app.logger.debug("username/keyid/fingerprint: " + username + "/" + str(keyid) + "/" + str(fingerprint))

    sshPublicCerts = []
    result = ""

    con = operations.open_ldap_connection()

    user = {}
    users = []
    users = search_users(con,'(&(' + LDAP_ATTR_OBJECTCLASS + '=*)(' + LDAP_ATTR_CN + '=' + username + '))')
    tnow = datetime.utcnow()

    if (len(users) > 0):
        user = users.pop()

    if not (LDAP_ATTR_CN in user):
        raise KeyperError(errors["UnauthorizedAccessError"].get("msg"), errors["UnauthorizedAccessError"].get("status"))

    if ("sshPublicCerts" in user):
        sshPublicCerts = user.get("sshPublicCerts")
    else:
        raise KeyperError(errors["SSHPublicCertNotExistError"].get("msg"), errors["SSHPublicCertNotExistError"].get("status"))

    if(len(sshPublicCerts) == 0):
        raise KeyperError(errors["SSHPublicCertNotExistError"].get("msg"), errors["SSHPublicCertNotExistError"].get("status"))

    for sshPublicCert in sshPublicCerts:
        cert = sshPublicCert.get("cert")
        dateExpire = datetime.strptime(sshPublicCert["dateExpire"],"%Y%m%d%H%M%S")
        keyFP = sshPublicCert["fingerprint"]
        keyID = int(sshPublicCert["keyid"])

        app.logger.debug("Cert Extracted")

        if (dateExpire > tnow):
            app.logger.debug("Cert is valid")
            if (((keyid is None) or (int(keyid) == keyID)) and ((fingerprint is None) or (fingerprint == keyFP))):
                result = result + cert + "\n"
            else:
                app.logger.debug("Fingerprints or keyid don't match. keyID/fingerprint: " + str(keyID) + "/" + keyFP)
        else:
            app.logger.debug("Cert Expired")

    operations.close_ldap_connection(con)
    
    app.logger.debug("Exit")
    return Response(result, mimetype='text/plain')

def isUserAuthorized(con, user, host):
    app.logger.debug("Enter")

    return_groups = set()

    user_dn = user["dn"]
    host_dn = LDAP_ATTR_CN + "=" + host + "," + app.config["LDAP_BASEHOST"]
    base_dn = app.config["LDAP_BASEGROUPS"]
    searchFilter = "(|(&(objectClass=groupOfNames)(member=" + user_dn + ")(cn=KeyperAdmins))(&(objectClass=groupOfNames)(member=" + user_dn + ")(member=" + host_dn + ")))"
    app.logger.debug("seachFilter:" + searchFilter)
    attrs = [LDAP_ATTR_DN,LDAP_ATTR_CN]


    try:
        if LDAP_ATTR_PWDACCOUNTLOCKEDTIME in user:
            app.logger.debug("Account is locked for user: " + user_dn)
        else:
            result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,searchFilter, attrs)

            app.logger.debug("Search Result length: " + str(len(result)))

            for dn, entry in result:
                return_groups.add(dn.lower())

    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return return_groups

def getSSHPublicKeys(con, user, host, fingerprint, user_groups):
    app.logger.debug("Enter")

    sshPublicKeys = []
    today = datetime.today()

    if ("sshPublicKeys" in user):
        for key in user["sshPublicKeys"]:
            sshPublicKey = key["key"]
            dateExpire = datetime.strptime(key["dateExpire"],"%Y%m%d%H%M%S")
            hostGroups = set(map(lambda grp: grp.lower(), key["hostGroups"]))
            keyFP = key["fingerprint"]

            app.logger.debug("Key Extracted")

            if (dateExpire > today):
                app.logger.debug("Key is valid")
                if ((fingerprint is None) or (fingerprint == keyFP)):
                    if (len(user_groups.intersection(hostGroups)) > 0):
                        sshPublicKeys.append(sshPublicKey)
                    else:
                        app.logger.debug("host not part of key's hostgroups")
                else:
                    app.logger.debug("Fingerprints don't match. Stored FP: " + keyFP + " Supplied FP: " + fingerprint)
            else:
                app.logger.debug("Key Expired")

    app.logger.debug("Number of Keys returned: " + str(len(sshPublicKeys)))
    app.logger.debug("Exit")

    return sshPublicKeys

def isHostInHostGroups(con, host, hostGroups):
    app.logger.debug("Enter")

    return_flag = False

    host_dn = LDAP_ATTR_CN + "=" + host + "," + app.config["LDAP_BASEHOST"]
    base_dn = app.config["LDAP_BASEGROUPS"]
    searchFilter = "(&(|"
    for group in hostGroups:
        groupCn = cn_from_dn(group)
        searchFilter += "(" + LDAP_ATTR_CN + "=" + groupCn + ")"
    searchFilter += ")(objectClass=groupOfNames)(member=" + host_dn + "))"
    app.logger.debug("seachFilter:" + searchFilter)
    attrs = [LDAP_ATTR_DN,LDAP_ATTR_CN]

    try:
        result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,searchFilter, attrs)

        app.logger.debug("Search Result length: " + str(len(result)))

        if (len(result) > 0):
            return_flag = True
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return return_flag

class AuthKeySchema(Schema):
    username = fields.Str(required=True, validate=Length(max=100))
    host = fields.Str(required=True, validate=Length(max=100))
    fingerprint = fields.Str(required=False, validate=Length(max=100))

    class Meta:
       fields = ("username", "host", "fingerprint")

class AuthPrincSchema(Schema):
    username = fields.Str(required=True, validate=Length(max=100))
    host = fields.Str(required=True, validate=Length(max=100))
    fingerprint = fields.Str(required=True, validate=Length(max=100))
    cert_serial = fields.Int(required=True)

    class Meta:
        fields = ("username", "host", "fingerprint", "cert_serial")

class HostCertSchema(Schema):
    hostname = fields.Str(required=True, validate=Length(max=100))
    keyid = fields.Int(required=False)
    fingerprint = fields.Str(required=False, validate=Length(max=100))

    class Meta:
        fields = ("hostname", "keyid", "fingerprint")

class UserCertSchema(Schema):
    username = fields.Str(required=True, validate=Length(max=100))
    keyid = fields.Int(required=False)
    fingerprint = fields.Str(required=False, validate=Length(max=100))

    class Meta:
        fields = ("username", "keyid", "fingerprint")

authkey_schema = AuthKeySchema()
authprinc_schema = AuthPrincSchema()
host_cert_schema = HostCertSchema()
user_cert_schema = UserCertSchema()
