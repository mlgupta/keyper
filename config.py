''' Application Config '''
class Config(object):
    ''' Application Config '''
    DEBUG = False
    TESTING = False
    LDAP_HOST = "fjord.dbsentry.com"
    LDAP_PORT = "389"
    LDAP_USER = "cn=Manager,dc=dbsentry,dc=com"
    LDAP_PASSWD = "success."
    LDAP_BASEDN = "dc=dbsentry,dc=com"
    LDAP_BASEUSER = "ou=people," + LDAP_BASEDN
    LDAP_BASEHOST = "ou=Hosts," + LDAP_BASEDN
    LDAP_BASEGROUPS = "ou=groups," + LDAP_BASEDN

    JWT_SECRET_KEY = 'super-duper-secret'

    LOG_TYPE = 'stream'
    LOG_LEVEL = 'DEBUG'


class ProductionConfig(Config):
    pass

class DevelopmentConfig(Config):
    LDAP_USER = "cn=manish,ou=people,dc=dbsentry,dc=com"
    LDAP_PASSWD = "success."
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
