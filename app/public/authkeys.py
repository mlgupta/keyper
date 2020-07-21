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

@public.route('/authkeys', methods=['GET'])
def get_authkeys():
    ''' Get SSH Public Keys '''
    app.logger.debug("Enter")

    req = request.args

    err = authkey_schema.validate(req)
    if err:
        app.logger.error("Input Data validation error.")
        app.logger.error("Errors:" + json.dumps(err))
        raise KeyperError(errors["SchemaValidationError"].get("message"), errors["SchemaValidationError"].get("status"))

    username = request.args.get('username')
    host = request.args.get('host')

    sshPublicKeys = []
    result = ""

    con = operations.open_ldap_connection()

    if (isUsernameAuthorized(con, username, host)):
        sshPublicKeys = getSSHPublicKeys(con, username)

    for sshPublicKey in sshPublicKeys:
        result = sshPublicKey + "\n"

    operations.close_ldap_connection(con)
    
    app.logger.debug("Exit")
    return Response(result, mimetype='text/plain')


def isUsernameAuthorized(con, username, host):
    app.logger.debug("Enter")
    app.logger.debug("Exit")

    return True

def getSSHPublicKeys(con, username):
    app.logger.debug("Enter")

    base_dn = app.config["LDAP_BASEUSER"]
    attrs = ['dn','cn','sshPublicKey']
    searchFilter = '(&(objectClass=*)(cn=' + username + '))'

    try:
        result = con.search_s(base_dn,ldap.SCOPE_ONELEVEL,searchFilter, attrs)

        for dn, entry in result:
            sshPublicKeys = []

            if ("sshPublicKey" in entry):
                for sshPublicKey in entry.get("sshPublicKey"):
                    sshPublicKeys.append(sshPublicKey.decode())

    except ldap.LDAPError:
        exctype, value = sys.exc_info()[:2]
        app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
        raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

    app.logger.debug("Exit")

    return sshPublicKeys

class AuthKeySchema(Schema):
    username = fields.Str(required=True, validate=Length(max=100))
    host = fields.Str(required=True, validate=Length(max=100))

    class Meta:
        fields = ("username", "host")

authkey_schema = AuthKeySchema()
