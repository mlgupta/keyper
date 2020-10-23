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
from os import environ

''' Application Config '''
class Config(object):
    ''' Application Config '''
    DEBUG = False
    TESTING = False

    KEYPER_VERSION = "0.1.8"
    
    LDAP_HOST = "localhost"
    LDAP_PORT = "389"
    LDAP_DOMAIN = environ.get("LDAP_DOMAIN", "keyper.example.org")

    LDAP_BASEDN = "dc=" + LDAP_DOMAIN.replace(".",",dc=")
    LDAP_BASEUSER = "ou=people," + LDAP_BASEDN
    LDAP_BASEHOST = "ou=Hosts," + LDAP_BASEDN
    LDAP_BASEGROUPS = "ou=groups," + LDAP_BASEDN
    LDAP_ALL_HOST_GROUP = "cn=AllHosts," + LDAP_BASEGROUPS

    LDAP_USER = "cn=Manager," + LDAP_BASEDN
    LDAP_PASSWD = environ.get("LDAP_ADMIN_PASSWORD", "superdupersecret")

    LDAP_PROTECTED_USERS = ["admin"]
    LDAP_PROTECTED_GROUPS = ["keyperadmins", "allhosts"]

    KEYPER_ADMIN_GROUP = "keyperadmins"

    JWT_ADMIN_ROLE = "keyper_admin"
    JWT_USER_ROLE = "keyper_user"
    JWT_SECRET_KEY = LDAP_PASSWD

    SSH_CA_DIR = environ.get("SSH_CA_DIR", "/etc/sshca")
    SSH_CA_HOST_KEY = environ.get("SSH_CA_HOST_KEY", "ca_host_key")
    SSH_CA_USER_KEY = environ.get("SSH_CA_USER_KEY", "ca_user_key")
    SSH_CA_TMP_WORK_DIR = environ.get("SSH_CA_TMP_WORK_DIR", "tmp")
    SSH_CA_TMP_DELETE_FLAG = True

    LOG_TYPE = 'stream'
    LOG_LEVEL = 'INFO'
#    LOG_DIR = "/var/log/keyper"
#    APP_LOG_NAME = "app.log"
#    WWW_LOG_NAME = "www.log"

class ProductionConfig(Config):
    pass

class DevelopmentConfig(Config):
    LDAP_HOST = "10.0.0.5"
    LDAP_PORT = "389"
    LDAP_PASSWD = environ.get("LDAP_ADMIN_PASSWORD", "success.")

    SSH_CA_DIR = environ.get("SSH_CA_DIR", "/Users/manish/ssh")
    SSH_CA_TMP_DELETE_FLAG = False

    LOG_TYPE = 'stream'
    LOG_LEVEL = 'DEBUG'

    DEBUG = True

class TestingConfig(Config):
    TESTING = True

config = {
    'dev': 'DevelopmentConfig',
    'prod': 'ProductionConfig',
}