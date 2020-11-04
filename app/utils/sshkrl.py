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
import struct
import base64
from flask import current_app as app
from ..resources.errors import KeyperError, errors

"""
Implements SSH KRL Lookup.
"""

class SSHKRL(object):
    ''' SSHKRL Class '''
    ca_host_key = ''
    ca_user_key = ''
    ca_krl_file = ''
    ca_tmp_work_dir = ''
    ca_tmp_work_delete_flag = True
    krl_buf_len = 0
    krl = {}

    def __init__(self):
        app.logger.debug("Enter")
        self.ca_dir = app.config["SSH_CA_DIR"]
        self.ca_host_key = self.ca_dir + "/" + app.config["SSH_CA_HOST_KEY"]
        self.ca_user_key = self.ca_dir + "/" + app.config["SSH_CA_USER_KEY"]
        self.ca_krl_file = self.ca_dir + "/" + app.config["SSH_CA_KRL_FILE"]
        self.ca_tmp_work_dir = self.ca_dir + "/" + app.config["SSH_CA_TMP_WORK_DIR"]
        self.ca_tmp_work_delete_flag = app.config["SSH_CA_TMP_DELETE_FLAG"]

        try:
            with open(self.ca_krl_file, mode="rb") as krl_file:
                krlbuf = krl_file.read()
                self.krl_buf_len = len(krlbuf)
                krl_buf_ptr = 0

                app.logger.debug("KRL File Size: " + str(self.krl_buf_len))

                # Parse headers
                if (self.krl_buf_len <= krl_buf_ptr + 48):
                    raise KeyperError(errors["KRLParseError"].get("msg"), errors["KRLParseError"].get("status"))

                self.krl["krl_sig"] = krlbuf[krl_buf_ptr:8]
                krl_buf_ptr += 8

                self.krl["krl_format_version"] = krlbuf[krl_buf_ptr:krl_buf_ptr+4]
                krl_buf_ptr += 4

                self.krl["krl_version"] = krlbuf[krl_buf_ptr:krl_buf_ptr+8]
                krl_buf_ptr += 8
                self.krl["krl_date"] = krlbuf[krl_buf_ptr:krl_buf_ptr+8]
                krl_buf_ptr += 8
                self.krl["krl_flags"] = krlbuf[krl_buf_ptr:krl_buf_ptr+8]
                krl_buf_ptr += 8

                string_size = struct.unpack('>i', krlbuf[krl_buf_ptr:krl_buf_ptr+4])[0]
                krl_buf_ptr += 4

                if (self.krl_buf_len < krl_buf_ptr + string_size):
                    app.logger.error("KRL Parse Error at reserved string " + str(krl_buf_ptr))
                    raise KeyperError(errors["KRLParseError"].get("msg"), errors["KRLParseError"].get("status"))

                krl_buf_ptr += string_size
                string_size = struct.unpack('>i', krlbuf[krl_buf_ptr:krl_buf_ptr+4])[0]
                krl_buf_ptr += 4

                if (self.krl_buf_len < krl_buf_ptr + string_size):
                    app.logger.error("KRL Parse Error at comment " + str(krl_buf_ptr))
                    raise KeyperError(errors["KRLParseError"].get("msg"), errors["KRLParseError"].get("status"))

                if (string_size > 0):
                    self.krl["krl_comment"] = krlbuf[krl_buf_ptr:krl_buf_ptr+string_size]
                    krl_buf_ptr += string_size
                
                # Parse sections
                while (krl_buf_ptr < self.krl_buf_len):
                    section_type = struct.unpack('c', krlbuf[krl_buf_ptr:krl_buf_ptr+1])[0]
                    krl_buf_ptr += 1
                    string_size = struct.unpack('>i', krlbuf[krl_buf_ptr:krl_buf_ptr+4])[0]
                    krl_buf_ptr += 4

                    if (self.krl_buf_len < krl_buf_ptr + string_size):
                        app.logger.error("KRL Parse Error at Sections " + str(krl_buf_ptr))
                        raise KeyperError(errors["KRLParseError"].get("msg"), errors["KRLParseError"].get("status"))

                    section_data = krlbuf[krl_buf_ptr:krl_buf_ptr+string_size]
                    krl_buf_ptr += string_size

                    if (section_type == b'\x01'):
                        section_ptr = 0
                        section_data_len = len(section_data)

                        if ("krl_certs" not in self.krl):
                            self.krl["krl_certs"] = []
                        while (section_ptr < section_data_len):
                            string_size = struct.unpack('>i', section_data[section_ptr:section_ptr+4])[0]
                            section_ptr += 4

                            if (section_data_len < section_ptr + string_size):
                                app.logger.error("KRL Parse Error at section 1. Section PTR: " + str(section_ptr))
                                raise KeyperError(errors["KRLParseError"].get("msg"), errors["KRLParseError"].get("status"))

                            krl_certs = {}

                            krl_certs["ca_key"] = section_data[section_ptr:section_ptr+string_size]
                            section_ptr += string_size

                            string_size = struct.unpack('>i', section_data[section_ptr:section_ptr+4])[0]
                            section_ptr += 4

                            if (section_data_len < section_ptr + string_size):
                                app.logger.error("KRL Parse Error at section 1. Section PTR: " + str(section_ptr))
                                raise KeyperError(errors["KRLParseError"].get("msg"), errors["KRLParseError"].get("status"))

                            section_ptr += string_size

                            cert_section_type = struct.unpack('c', section_data[section_ptr:section_ptr+1])[0]
                            section_ptr += 1

                            string_size = struct.unpack('>i', section_data[section_ptr:section_ptr+4])[0]
                            section_ptr += 4

                            if (section_data_len < section_ptr + string_size):
                                app.logger.error("KRL Parse Error at section 1. Section PTR: " + str(section_ptr))
                                raise KeyperError(errors["KRLParseError"].get("msg"), errors["KRLParseError"].get("status"))

                            if (cert_section_type == b'\x20'):
                                cert_serial_list = section_data[section_ptr:section_ptr+string_size]
                                section_ptr += string_size

                                cert_serial_list_ptr = 0
                                cert_serial_list_len = len(cert_serial_list)

                                krl_certs["cert_serial_list"] = []
                                while (cert_serial_list_ptr < cert_serial_list_len):
                                    krl_certs["cert_serial_list"].append(struct.unpack('>q', cert_serial_list[cert_serial_list_ptr:cert_serial_list_ptr+8])[0])
                                    app.logger.debug("Cert Serial No: " + str(struct.unpack('>q', cert_serial_list[cert_serial_list_ptr:cert_serial_list_ptr+8])[0]))
                                    cert_serial_list_ptr += 8
                                app.logger.debug("Cert Serial List Size: " + str(len(krl_certs["cert_serial_list"])))
                            else:
                                section_ptr += string_size

                            self.krl["krl_certs"].append(krl_certs)
                    elif (section_type == b'\x02'):
                        section_ptr = 0
                        section_data_len = len(section_data)
                        if ("krl_keys" not in self.krl):
                            self.krl["krl_keys"] = []
                        while (section_ptr < section_data_len):
                            string_size = struct.unpack('>i', section_data[section_ptr:section_ptr+4])[0]
                            section_ptr += 4

                            if (section_data_len < section_ptr + string_size):
                                app.logger.error("KRL Parse Error at section 2. Section PTR: " + str(section_ptr))
                                raise KeyperError(errors["KRLParseError"].get("msg"), errors["KRLParseError"].get("status"))

                            self.krl["krl_keys"].append(section_data[section_ptr:section_ptr+string_size])
                            section_ptr += string_size
                        app.logger.debug("KRL Keys Size: " + str(len(self.krl["krl_keys"])))
                    elif (section_type == b'\x05'):
                        section_ptr = 0
                        section_data_len = len(section_data)
                        if ("krl_key_hash" not in self.krl):
                            self.krl["krl_key_hash"] = []
                        while (section_ptr < section_data_len):
                            string_size = struct.unpack('>i', section_data[section_ptr:section_ptr+4])[0]
                            section_ptr += 4

                            if (section_data_len < section_ptr + string_size):
                                app.logger.error("KRL Parse Error at section 5. Section PTR: " + str(section_ptr))
                                raise KeyperError(errors["KRLParseError"].get("msg"), errors["KRLParseError"].get("status"))

                            self.krl["krl_key_hash"].append(section_data[section_ptr:section_ptr+string_size])
                            app.logger.debug("Key Hash: " + section_data[section_ptr:section_ptr+string_size].hex())
                            section_ptr += string_size
                        app.logger.debug("KRL Key Hash Size: " + str(len(self.krl["krl_key_hash"])))
        except OSError as e:
            app.logger.error("OS error: " + str(e))
            raise KeyperError(errors["OSError"].get("msg"), errors["OSError"].get("status"))

        app.logger.debug("Exit")

    def is_key_revoked(self, key_hash):
        ''' Checks if key hash in KRL '''
        app.logger.debug("Enter")

        rc = False

        try:
            app.logger.debug("key_hash: " + key_hash)
            key_hash_split = key_hash.split(":")[1]
            app.logger.debug("key_hash split: " + key_hash_split)

            missing_padding = len(key_hash_split) + 4 - (len(key_hash_split) % 4) 
            app.logger.debug("missing padding: " + str(missing_padding))
            key_hash_split = key_hash_split.ljust(missing_padding, '=')
            app.logger.debug("key_hash_split:" + key_hash_split)
            
            decoded_hash = base64.b64decode(key_hash_split)
            if ("krl_key_hash" in self.krl):
                if (decoded_hash in self.krl["krl_key_hash"]):
                    rc = True
        except OSError as e:
            app.logger.error("OS error: " + str(e))
            raise KeyperError(errors["OSError"].get("msg"), errors["OSError"].get("status"))

        app.logger.debug("Exit")
        return rc

    def is_cert_revoked(self, cert_serial):
        ''' Checks if cert serial in KRL '''
        app.logger.debug("Enter")

        rc = False

        try:
            app.logger.debug("cert_serial: " + str(cert_serial))
            if ("krl_certs" in self.krl):
                for krl_cert in self.krl["krl_certs"]:
                    if (cert_serial in krl_cert["cert_serial_list"]):
                        rc = True
                        break
        except OSError as e:
            app.logger.error("OS error: " + str(e))
            raise KeyperError(errors["OSError"].get("msg"), errors["OSError"].get("status"))

        app.logger.debug("Exit")
        return rc
