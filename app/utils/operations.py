''' Common methods go here '''
import ldap
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
