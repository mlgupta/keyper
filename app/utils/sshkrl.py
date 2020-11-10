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
    ca_krl_file = ''
    krl_buf_len = 0
    krl = {}

    def __init__(self):
        app.logger.debug("Enter")
        self.ca_dir = app.config["SSH_CA_DIR"]
        self.ca_krl_file = self.ca_dir + "/" + app.config["SSH_CA_KRL_FILE"]

        try:
            with open(self.ca_krl_file, mode="rb") as krl_file:
                krlbuf = krl_file.read()
                self.krl_buf_len = len(krlbuf)
                krl_buf_ptr = 0

                app.logger.debug("KRL File Size: " + str(self.krl_buf_len))

                # Parse headers
                if (self.krl_buf_len < krl_buf_ptr + 44):
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

                krl_buf_ptr, reserved_string = self.read_string_from_buf(krlbuf, krl_buf_ptr)
                krl_buf_ptr, self.krl["krl_comment"] = self.read_string_from_buf(krlbuf, krl_buf_ptr)

                # Parse sections
                while (krl_buf_ptr < self.krl_buf_len):
                    section_type = struct.unpack('c', krlbuf[krl_buf_ptr:krl_buf_ptr+1])[0]
                    krl_buf_ptr += 1

                    krl_buf_ptr, section_data = self.read_string_from_buf(krlbuf, krl_buf_ptr)

                    if (section_type == b'\x01'):
                        section_ptr = 0
                        section_data_len = len(section_data)

                        if ("krl_certs" not in self.krl):
                            self.krl["krl_certs"] = []
                        while (section_ptr < section_data_len):
                            krl_certs = {}
                            section_ptr, krl_certs["ca_key"] = self.read_string_from_buf(section_data, section_ptr)
                            section_ptr, reserved_string = self.read_string_from_buf(section_data, section_ptr)

                            cert_section_type = struct.unpack('c', section_data[section_ptr:section_ptr+1])[0]
                            section_ptr += 1

                            section_ptr, cert_serial_list = self.read_string_from_buf(section_data, section_ptr)

                            if (cert_section_type == b'\x20'):
                                cert_serial_list_ptr = 0
                                cert_serial_list_len = len(cert_serial_list)

                                krl_certs["cert_serial_list"] = []
                                while (cert_serial_list_ptr < cert_serial_list_len):
                                    krl_certs["cert_serial_list"].append(struct.unpack('>q', cert_serial_list[cert_serial_list_ptr:cert_serial_list_ptr+8])[0])
                                    app.logger.debug("Cert Serial No: " + str(struct.unpack('>q', cert_serial_list[cert_serial_list_ptr:cert_serial_list_ptr+8])[0]))
                                    cert_serial_list_ptr += 8
                                app.logger.debug("Cert Serial List Size: " + str(len(krl_certs["cert_serial_list"])))

                            self.krl["krl_certs"].append(krl_certs)
                    elif (section_type == b'\x02'):
                        section_ptr = 0
                        section_data_len = len(section_data)
                        if ("krl_keys" not in self.krl):
                            self.krl["krl_keys"] = []
                        
                        while (section_ptr < section_data_len):
                            section_ptr, krl_key = self.read_string_from_buf(section_data, section_ptr)
                            self.krl["krl_keys"].append(krl_key)

                        app.logger.debug("KRL Keys Size: " + str(len(self.krl["krl_keys"])))
                    elif (section_type == b'\x05'):
                        section_ptr = 0
                        section_data_len = len(section_data)
                        if ("krl_key_hash" not in self.krl):
                            self.krl["krl_key_hash"] = []
                        while (section_ptr < section_data_len):
                            section_ptr, krl_key_hash = self.read_string_from_buf(section_data, section_ptr)
                            self.krl["krl_key_hash"].append(krl_key_hash)
                            app.logger.debug("Key Hash: " + str(krl_key_hash))

                        app.logger.debug("KRL Key Hash Size: " + str(len(self.krl["krl_key_hash"])))
        except OSError as e:
            app.logger.error("OS error: " + str(e))
            raise KeyperError(errors["OSError"].get("msg"), errors["OSError"].get("status"))

        app.logger.debug("Exit")

    def read_string_from_buf(self, buf, ptr):
        ''' Returns a string from buffer '''
        app.logger.debug("Enter")

        result_string = None
        result_ptr = ptr
        buf_len = len(buf)

        string_size = struct.unpack('>i', buf[result_ptr:result_ptr+4])[0]
        result_ptr += 4

        if (buf_len < result_ptr + string_size):
            app.logger.error("KRL Parse Error at section. PTR: " + str(result_ptr))
            raise KeyperError(errors["KRLParseError"].get("msg"), errors["KRLParseError"].get("status"))

        result_string = buf[result_ptr:result_ptr+string_size]
        result_ptr += string_size

        app.logger.debug("Exit")
        return result_ptr, result_string

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
                    app.logger.debug("Revoked serial list: " + str(krl_cert["cert_serial_list"]))
                    if (cert_serial in krl_cert["cert_serial_list"]):
                        rc = True
                        break
        except OSError as e:
            app.logger.error("OS error: " + str(e))
            raise KeyperError(errors["OSError"].get("msg"), errors["OSError"].get("status"))

        app.logger.debug("Exit")
        return rc
