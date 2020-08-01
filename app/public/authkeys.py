''' API to get user's SSH Public Keys '''
import sys
import json
import ldap
from flask import request, Response
from flask import current_app as app
from marshmallow import fields, Schema
from marshmallow.validate import Length
from . import public
from ..resources.errors import KeyperError, errors
from ..utils import operations
from ..admin.users import search_users

@public.route('/authkeys', methods=['GET'])
def get_authkeys():
    ''' Get SSH Public Keys '''
    app.logger.debug("Enter")

    req = request.args

    err = authkey_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("msg"), errors["SchemaValidationError"].get("status"))

    username = request.args.get('username')
    host = request.args.get('host')

    sshPublicKeys = []
    result = ""

    con = operations.open_ldap_connection()

    user = {}
    user = search_users(con,'(&(objectClass=*)(cn=' + username + '))').pop()

    if not ("cn" in user):
        raise KeyperError(errors["UnauthorizedAccessError"].get("msg"), errors["UnauthorizedAccessError"].get("status"))

    if (isUserAuthorized(con, user, host)):
        sshPublicKeys = getSSHPublicKeys(user)
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

    return True

def getSSHPublicKeys(user):
    app.logger.debug("Enter")

    sshPublicKeys = []

    if ("sshPublicKeys" in user):
        for sshPublicKey in user["sshPublicKeys"]:
            sshPublicKeys.append(sshPublicKey)

    app.logger.debug("Keys returned: " + str(len(sshPublicKeys)))
    app.logger.debug("Exit")

    return sshPublicKeys

class AuthKeySchema(Schema):
    username = fields.Str(required=True, validate=Length(max=100))
    host = fields.Str(required=True, validate=Length(max=100))

    class Meta:
        fields = ("username", "host")

authkey_schema = AuthKeySchema()
