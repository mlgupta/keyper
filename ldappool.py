class LDAPConnection:

    __con = None

    def __init__(self):
        app.logger.debug("Enter")

        ldapHost = app.config["LDAP_HOST"]
        ldapPort = app.config["LDAP_PORT"]
        ldapUserName = app.config["LDAP_USER"]
        ldapPasswd = app.config["LDAP_PASSWD"]

        server = 'ldap://' + ldapHost + ":" + ldapPort

        try:
            __con = ldap.initialize(server)
            __con.simple_bind_s(ldapUserName, ldapPasswd)
            app.logger.debug("Exit")
        except ldap.INVALID_CREDENTIALS:
            app.logger.error("Authentication failure. Invalid Credentials")
            raise KeyperError(errors["UnauthorizedError"].get("message"), errors["UnauthorizedError"].get("status"))
        except ldap.LDAPError as e:
            exctype, value = sys.exc_info()[:2]
            app.logger.error("LDAP Exception " + str(exctype) + " " + str(value))
            raise KeyperError("LDAP Exception " + str(exctype) + " " + str(value),401)

        app.logger.debug("Exit")


    def reset(self):
        """ Put resource back into default setting. """
        self.__con = None

    def setCon(self, con):
        self.__con = con

    def getCon(self):
        return self.__con


class ObjectPool:
    
    """ Resource manager.
    Handles checking out and returning resources from clients.
    It's a singleton class.
    """

    __instance = None
    __resources = list()

    def __init__(self):
        app.logger.debug("Enter")
        if ObjectPool.__instance != None:
            raise NotImplemented("This is a singleton class.")
        app.logger.debug("Exit")

    @staticmethod
    def getInstance():
        app.logger.debug("Enter")
        if ObjectPool.__instance == None:
            ObjectPool.__instance = ObjectPool()

        app.logger.debug("Exit")
        return ObjectPool.__instance

    def getResource(self):
        app.logger.debug("Enter")
        app.logger.debug("Exit")
        if len(self.__resources) > 0:
            print "Using existing resource."
            return self.__resources.pop(0)
        else:
            print "Creating new resource."
            return LDAPConnection()

    def returnResource(self, resource):
        app.logger.debug("Enter")
        #resource.reset()
        self.__resources.append(resource)
        app.logger.debug("Exit")
