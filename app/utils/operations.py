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
''' Common methods go here '''
import ldap
from datetime import datetime, timedelta
from flask import current_app as app
from ..resources.errors import KeyperError, errors

def open_ldap_connection():
    """ Open LDAP Connection and return the same. """
    app.logger.debug("Enter")

    ldapHost = app.config["LDAP_HOST"]
    ldapPort = app.config["LDAP_PORT"]
    ldapUserName = app.config["LDAP_USER"]
    ldapPasswd = app.config["LDAP_PASSWD"]

    server = 'ldap://' + ldapHost + ":" + ldapPort

    try:
        con = ldap.initialize(server)
        con.simple_bind_s(ldapUserName, ldapPasswd)
    except ldap.INVALID_CREDENTIALS:
        app.logger.error("Authentication failure. Invalid Credentials")
        raise KeyperError(errors["UnauthorizedError"].get("msg"), errors["UnauthorizedError"].get("status"))
    except ldap.LDAPError as e:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")
    return(con)

def open_ldap_connection_no_bind():
    """ Open LDAP Connection and return the same. """
    app.logger.debug("Enter")

    ldapHost = app.config["LDAP_HOST"]
    ldapPort = app.config["LDAP_PORT"]

    server = 'ldap://' + ldapHost + ":" + ldapPort

    try:
        con = ldap.initialize(server)
    except ldap.LDAPError as e:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")
    return(con)


def close_ldap_connection(con):
    """ Close LDAP Connection """
    app.logger.debug("Enter")

    try:
        con.unbind_s()
    except ldap.LDAPError as e:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

def duration_to_date_expire(duration, duration_unit):
    """ Returns expire date per duration """
    app.logger.debug("Enter")

    app.logger.debug("duration/duration_unit: " + duration + "/" + duration_unit)
    
    kwargs = { duration_unit.lower(): int(duration) }
    date_expire = datetime.utcnow() + timedelta(**kwargs)

    app.logger.debug("date_expire: " + date_expire.strftime("%Y%m%d%H%M%S"))

    app.logger.debug("Exit")
    return date_expire.strftime("%Y%m%d%H%M%S")

def ssh_duration(duration, duration_unit):
    """ Returns  duration """
    app.logger.debug("Enter")

    app.logger.debug("duration/duration_unit: " + duration + "/" + duration_unit)

    result = duration;

    if (duration_unit == "Hours"):
        result += "h"
    elif (duration_unit == "Days"):
        result += "d"
    elif (duration_unit == "Weeks"):
        result += "w"

    app.logger.debug("ssh duration: " + result)

    app.logger.debug("Exit")
    return result

