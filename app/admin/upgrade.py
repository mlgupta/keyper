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
''' Upgrade older version '''
import sys
import json
import ldap
from setuptools._vendor.packaging import version
from flask import request, jsonify
from flask import current_app as app
from flask_jwt_extended import create_access_token, create_refresh_token, get_raw_jwt, jwt_required
from flask_jwt_extended import jwt_refresh_token_required, get_jwt_identity, get_jwt_claims
from datetime import datetime
from . import admin
from ..resources.errors import KeyperError, errors
from ..utils import operations
from ..utils.extensions import *
from ldapDefn import *

@admin.route('/upgrade', methods=['GET','POST'])
@jwt_required
@requires_keyper_admin()
def upgrade():
    ''' Upgrade older version '''
    app.logger.debug("Enter")

    try:
        con = operations.open_ldap_connection()

        keyper_version_ldap = get_keyper_ldap_version(con)
        keyper_version = app.config["KEYPER_VERSION"]
        return_code = 200
        return_message = {}

        if (keyper_version_ldap == "" or version.parse(keyper_version_ldap) < version.parse(keyper_version)):
            app.logger.debug("keyper_ldap_version/keyper_version: " + keyper_version_ldap + "/" + keyper_version)
            app.logger.debug("Upgrading...")

            if (keyper_version_ldap == ""):
                upgrade_to_0_1_8(con)
        
            keyper_version_ldap = get_keyper_ldap_version(con)

            if (version.parse(keyper_version_ldap) < version.parse(keyper_version)):
                set_keyper_ldap_version(con, keyper_version)

            return_message["msg"] = "Keyper LDAP successfully upgraded to version: " + keyper_version
        else:
            app.logger.debug("Versions equal. No need to upgrade: " + keyper_version)
            return_message["msg"] = "Versions equal. No need to upgrade: " + keyper_version

    except ldap.NO_SUCH_OBJECT:
        app.logger.error("Unable to delete. LDAP Entry not found:" + dn)
        raise KeyperError(errors["ObjectDeleteError"].get("msg"), errors["ObjectDeleteError"].get("status"))
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return jsonify(return_message), return_code

def get_keyper_ldap_version(con):
    ''' Get Keyper Version in LDAP '''
    app.logger.debug("Enter")

    base_dn = app.config["LDAP_BASEDN"]
    attrs = [LDAP_ATTR_DN,LDAP_ATTR_DESCRIPTION]
    version = ""

    try:
        #searchFilter = '(' + LDAP_ATTR_OBJECTCLASS + '= dcObject)'
        result = con.search_s(base_dn,ldap.SCOPE_BASE,None,attrs)

        description = ""

        for dn, entry in result:
            if (LDAP_ATTR_DESCRIPTION in entry):
                for i in entry.get(LDAP_ATTR_DESCRIPTION):
                    description = json.loads(i.decode())
        
        if ("version" in description):
            version = description.get("version")

    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return version

def set_keyper_ldap_version(con, version):
    ''' Get Keyper Version in LDAP '''
    app.logger.debug("Enter")

    base_dn = app.config["LDAP_BASEDN"]

    try:
        mod_list = []

        description = {}
        description["version"] = version
        mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_DESCRIPTION,json.dumps(description).encode()))

        con.modify_s(base_dn,mod_list)
    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return 0

def upgrade_to_0_1_8(con):
    ''' Upgrade Keyper Version in LDAP to 0.1.8 '''
    app.logger.debug("Enter")

    try:
        base_dn = app.config["LDAP_BASEHOST"]
        attrs = [LDAP_ATTR_DN]

        app.logger.info("Upgrading Hosts")
        host_count = 0

        result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,None,attrs)

        for dn, entry in result:
            mod_list = []
            mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_OBJECTCLASS,LDAP_OBJECTCLASS_HOST))
            con.modify_s(dn,mod_list)
            host_count += 1

        if (host_count > 0):
            app.logger.info("Upgraded Host Count: " + str(host_count))

        base_dn = app.config["LDAP_BASEUSER"]
        attrs = [LDAP_ATTR_DN, LDAP_ATTR_SSHPUBLICKEY]

        app.logger.debug("Upgrading users")

        user_count = 0

        result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,None,attrs)

        for dn, entry in result:
            mod_list = []
            mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_OBJECTCLASS,LDAP_OBJECTCLASS_USER))

            if ("cn=admin" in dn.lower()):
                mod_list.append((ldap.MOD_ADD,LDAP_ATTR_PWDATTRIBUTE,["userPassword".encode()]))

            sshPublicKeys = []
            keyid = 0
            keytype = 0
            if (LDAP_ATTR_SSHPUBLICKEY in entry):
                for key in entry.get(LDAP_ATTR_SSHPUBLICKEY):
                    sshPublicKey = {}
                    app.logger.debug(key.decode())
                    sshPublicKey = json.loads(key.decode())
                    if not ("keyid" in sshPublicKey):
                        sshPublicKey["keyid"] = keyid
                    if not ("keytype" in sshPublicKey):
                        sshPublicKey["keytype"] = keytype
                    if ("dateExpire" in sshPublicKey):
                        dd = sshPublicKey.get("dateExpire")
                        dateExpire = datetime.strptime(dd,"%Y%m%d")
                        dd = dateExpire.strftime("%Y%m%d%H%M%S")
                        sshPublicKey["dateExpire"] = dd

                    sshPublicKeys.append(sshPublicKey)
                    keyid += 1
                if (len(sshPublicKeys) > 0):
                    sshPublicKeys = list(map(lambda key: json.dumps(key).encode(), sshPublicKeys))
                    mod_list.append((ldap.MOD_REPLACE,LDAP_ATTR_SSHPUBLICKEY,sshPublicKeys))

            con.modify_s(dn,mod_list)
            user_count += 1

        if (user_count > 0):
            app.logger.info("Upgraded User Count: " + str(user_count))

        set_keyper_ldap_version(con, "0.1.8")

    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

