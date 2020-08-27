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
from flask import request, Response
from flask import current_app as app
from marshmallow import fields, Schema
from marshmallow.validate import Length
from datetime import datetime
from . import public
from ..resources.errors import KeyperError, errors
from ..utils import operations
from ..admin.users import search_users, cn_from_dn

@public.route('/authkeys', methods=['GET','POST'])
def get_authkeys():
    ''' Get SSH Public Keys '''
    app.logger.debug("Enter")

    #req = request.args
    req = request.values

    err = authkey_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    #username = request.args.get('username')
    #host = request.args.get('host')
    username = request.values.get('username')
    host = request.values.get('host')

    app.logger.debug("username/host: " + username + "/" + host)

    sshPublicKeys = []
    result = ""

    con = operations.open_ldap_connection()

    user = {}
    user = search_users(con,'(&(objectClass=*)(cn=' + username + '))').pop()

    if not ("cn" in user):
        raise KeyperError(errors["UnauthorizedAccessError"].get("msg"), errors["UnauthorizedAccessError"].get("status"))

    if (isUserAuthorized(con, user, host)):
        sshPublicKeys = getSSHPublicKeys(con, user, host)
    else:
        raise KeyperError(errors["UnauthorizedAccessError"].get("msg"), errors["UnauthorizedAccessError"].get("status"))

    for sshPublicKey in sshPublicKeys:
        result = sshPublicKey + "\n"

    operations.close_ldap_connection(con)
    
    app.logger.debug("Exit")
    return Response(result, mimetype='text/plain')


def isUserAuthorized(con, user, host):
    app.logger.debug("Enter")

    return_flag = False

    user_dn = user["dn"]
    host_dn = "cn=" + host + "," + app.config["LDAP_BASEHOST"]
    base_dn = app.config["LDAP_BASEGROUPS"]
    searchFilter = "(|(&(objectClass=groupOfNames)(member=" + user_dn + ")(cn=Admins))(&(objectClass=groupOfNames)(member=" + user_dn + ")(member=" + host_dn + ")))"
    app.logger.debug("seachFilter:" + searchFilter)
    attrs = ['dn','cn']

    if "pwdAccountLockedTime" in user:
        app.logger.debug("Account is locked for user: " + user_dn)
        return_flag = False

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

def getSSHPublicKeys(con, user, host):
    app.logger.debug("Enter")

    sshPublicKeys = []
    today = datetime.today()

    if ("sshPublicKeys" in user):
        for key in user["sshPublicKeys"]:
            hostGroups = []
            sshPublicKey = key["key"]
            dateExpire = datetime.strptime(key["dateExpire"],"%Y%m%d")
            hostGroups = key["hostGroups"]

            app.logger.debug("Key Extracted")

            if (dateExpire > today):
                app.logger.debug("Key is valid")
                if (isHostInHostGroups(con, host, hostGroups)):
                    sshPublicKeys.append(sshPublicKey)
                else:
                    app.logger.debug("host not part of key's hostgroups")
            else:
                app.logger.debug("Key Expired")

    app.logger.debug("Number of Keys returned: " + str(len(sshPublicKeys)))
    app.logger.debug("Exit")

    return sshPublicKeys

def isHostInHostGroups(con, host, hostGroups):
    app.logger.debug("Enter")

    return_flag = False

    host_dn = "cn=" + host + "," + app.config["LDAP_BASEHOST"]
    base_dn = app.config["LDAP_BASEGROUPS"]
    searchFilter = "(&(|"
    for group in hostGroups:
        groupCn = cn_from_dn(group)
        searchFilter += "(cn=" + groupCn + ")"
    searchFilter += ")(objectClass=groupOfNames)(member=" + host_dn + "))"
    app.logger.debug("seachFilter:" + searchFilter)
    attrs = ['dn','cn']

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

    class Meta:
        fields = ("username", "host")

authkey_schema = AuthKeySchema()
