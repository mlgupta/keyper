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
''' Error definition '''

class KeyperError(Exception):
    ''' Keyper Error '''
    status_code = 400

    def __init__(self, msg, status_code=None, payload=None):
        Exception.__init__(self)
        self.msg = msg
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['msg'] = self.msg
        return rv

errors = {
    "InternalServerError": {
        "msg": "Something went wrong",
        "status": 500
    },
     "SchemaValidationError": {
         "msg": "Request is missing required fields or error in fields",
         "status": 400
     },
     "ObjectExistsError": {
         "msg": "Object with given name already exists",
         "status": 400
     },
     "ObjectUpdateError": {
         "msg": "Object Update Error",
         "status": 403
     },
     "ObjectDeleteError": {
         "msg": "Object Delete Error",
         "status": 403
     },
     "ObjectProtectedError": {
         "msg": "Protected Object Delete Not Allowed",
         "status": 403
     },
     "ObjectNotExistsError": {
         "msg": "Object with given id doesn't exists",
         "status": 400
     },
     "UnauthorizedError": {
         "msg": "Authentication Error. Invalid username or password",
         "status": 401
     },
     "UnauthorizedAccessError": {
         "msg": "Not Authorized to Access this resource",
         "status": 401
     },
     "TokenExpiredError": {
         "msg": "Token Expired",
         "status": 401
     },
     "SSHPublicKeyError": {
         "msg": "SSH Public Key Error",
         "status": 403
     },
     "SSHPublicKeyParseError": {
         "msg": "SSH Public Key Parse Error",
         "status": 403
     },
     "SSHPublicKeyInvalidError": {
         "msg": "SSH Public Key Invalid",
         "status": 403
     },
     "SSHPublicKeyRevokedError": {
         "msg": "SSH Public Key in Key Revocation List (KRL).",
         "status": 403
     },
     "OSError": {
         "msg": "OS Error",
         "status": 403
     },
     "SSHPublicCertError": {
         "msg": "SSH Public Cert Error",
         "status": 403
     },
     "SSHPublicCertNotExistError": {
         "msg": "SSH Public Cert does not exist",
         "status": 403
     },
     "KRLParseError": {
         "msg": "KRL Parse Error",
         "status": 403
     }
}
