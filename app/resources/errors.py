''' Error definition '''

class KeyperError(Exception):
    ''' Keyper Error '''
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv

errors = {
    "InternalServerError": {
        "message": "Something went wrong",
        "status": 500
    },
     "SchemaValidationError": {
         "message": "Request is missing required fields or error in fields",
         "status": 400
     },
     "ObjectExistsError": {
         "message": "Object with given name already exists",
         "status": 400
     },
     "ObjectUpdateError": {
         "message": "Object Update Error",
         "status": 403
     },
     "ObjectDeleteError": {
         "message": "Object Delete Error",
         "status": 403
     },
     "ObjectNotExistsError": {
         "message": "Object with given id doesn't exists",
         "status": 400
     },
     "UnauthorizedError": {
         "message": "Authentication Error. Invalid username or password",
         "status": 401
     },
     "UnauthorizedAccessError": {
         "message": "Not Authorized to Access this resource",
         "status": 401
     },
     "TokenExpiredError": {
         "message": "Token Expired",
         "status": 401
     }
}
