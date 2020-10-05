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
LDAP_ATTR_DN = "dn"

LDAP_ATTR_CN = "cn"
LDAP_ATTR_UID = "uid"
LDAP_ATTR_SN = "sn"
LDAP_ATTR_GIVENNAME = "givenName"
LDAP_ATTR_DISPLAYNAME = "displayName"
LDAP_ATTR_PWDACCOUNTLOCKEDTIME = "pwdAccountLockedTime"
LDAP_ATTR_MEMBEROF = "memberOf"
LDAP_ATTR_MAIL = "mail"
LDAP_ATTR_SSHPUBLICKEY = "sshPublicKey"
LDAP_ATTR_USERPASSWORD = "userPassword"
LDAP_ATTR_PWDATTRIBUTE = "pwdAttribute"
LDAP_ATTR_OWNER = "owner"
LDAP_ATTR_DESCRIPTION = "description"

LDAP_ATTR_OBJECTCLASS = "objectClass"

LDAP_ATTR_MEMBER = "member"

LDAP_OBJECTCLASS_USER = [b'inetOrgPerson',b'top',b'ldapPublicKey',b'pwdPolicy']
LDAP_OBJECTCLASS_HOST = [b'device',b'top']
LDAP_OBJECTCLASS_GROUP = [b'groupOfNames',b'top']


