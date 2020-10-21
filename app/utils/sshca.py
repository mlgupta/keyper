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
import subprocess
import os
import random
from tempfile import NamedTemporaryFile
from datetime import datetime
from flask import current_app as app
from ..resources.errors import KeyperError, errors

"""
Implements SSH CA. Two SSH CA are used: one for host and one for users.
"""

class SSHCA(object):
    ''' SSHCA Class '''
    ca_host_key = ''
    ca_user_key = ''
    ca_tmp_work_dir = ''
    ca_tmp_work_delete_flag = True

    def __init__(self):
        app.logger.debug("Enter")
        self.ca_host_key = app.config["SSH_CA_HOST_KEY"]
        self.ca_user_key = app.config["SSH_CA_USER_KEY"]
        self.ca_tmp_work_dir = app.config["SSH_CA_TMP_WORK_DIR"]
        self.ca_tmp_work_delete_flag = app.config["SSH_CA_TMP_DELETE_FLAG"]
        app.logger.debug("Exit")

    def sign_user_key(self, userkey, duration, owner, principal_list):
        ''' Sign User Key using User CA Key '''
        app.logger.debug("Enter")

        serial = random.getrandbits(64)
        signed_key = ''
        cert_file_full_path = ''

        try:
            with NamedTemporaryFile(mode='w+t',  dir=self.ca_tmp_work_dir, delete=self.ca_tmp_work_delete_flag, suffix='.pub') as key_file:
                app.logger.debug("Key: " + userkey)
                key_file.write(userkey)
                key_file.flush()

                key_file_full_path = key_file.name
                app.logger.debug("Key File: " + key_file_full_path)

                now = datetime.now().strftime("%Y%m%d%H%M%S")

                subprocess.call([
                    'ssh-keygen',
                    '-s', '{}'.format(self.ca_user_key),
                    '-z', str(serial),
                    '-I', owner,
                    '-V', '{}:{}'.format(now, duration),
                    '-n', principal_list,
                    '-q',
                    key_file_full_path])
                
                cert_file_full_path = key_file_full_path.rsplit('.',1)[0] + "-cert.pub"
                key_file.close()

            with open(cert_file_full_path, 'r') as cert_file:
                signed_key = cert_file.read()
                cert_file.close()

            if (os.path.exists(cert_file_full_path) and self.ca_tmp_work_delete_flag):
                os.remove(cert_file_full_path)

        except subprocess.SubprocessError as e:
            app.logger.error("ssh-keygen error: " + str(e))
            raise KeyperError(errors["SSHPublicKeyError"].get("msg"), errors["SSHPublicKeyError"].get("status"))
        except OSError as e:
            app.logger.error("OS error: " + str(e))
            raise KeyperError(errors["OSError"].get("msg"), errors["OSError"].get("status"))

        app.logger.debug("Exit")
        return signed_key

    def sign_host_key(self, hostkey, duration, hostname, principal_list):
        ''' Sign Host Key using Host CA Key '''
        app.logger.debug("Enter")

        serial = random.getrandbits(64)
        signed_key = ''
        cert_file_full_path = ''

        try:
            with NamedTemporaryFile(mode='w+t',  dir=self.ca_tmp_work_dir, delete=self.ca_tmp_work_delete_flag, suffix='.pub') as key_file:
                app.logger.debug("Key: " + hostkey)
                key_file.write(hostkey)
                key_file.flush()

                key_file_full_path = key_file.name
                app.logger.debug("Key File: " + key_file_full_path)

                now = datetime.now().strftime("%Y%m%d%H%M%S")

                subprocess.call([
                    'ssh-keygen',
                    '-h',
                    '-s', '{}'.format(self.ca_host_key),
                    '-z', str(serial),
                    '-I', hostname,
                    '-V', '{}:{}'.format(now, duration),
                    '-n', principal_list,
                    '-q',
                    key_file_full_path])
                
                cert_file_full_path = key_file_full_path.rsplit('.',1)[0] + "-cert.pub"
                key_file.close()

            with open(cert_file_full_path, 'r') as cert_file:
                signed_key = cert_file.read()
                cert_file.close()

            if (os.path.exists(cert_file_full_path) and self.ca_tmp_work_delete_flag):
                os.remove(cert_file_full_path)

        except subprocess.SubprocessError as e:
            app.logger.error("ssh-keygen error: " + str(e))
            raise KeyperError(errors["SSHPublicKeyError"].get("msg"), errors["SSHPublicKeyError"].get("status"))
        except OSError as e:
            app.logger.error("OS error: " + str(e))
            raise KeyperError(errors["OSError"].get("msg"), errors["OSError"].get("status"))

        app.logger.debug("Exit")
        return signed_key

