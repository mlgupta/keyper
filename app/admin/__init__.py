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
''' Init admin '''
from flask import Blueprint

admin = Blueprint('admin', __name__)

import logging
from datetime import datetime as dt
from flask import current_app as app
from flask import request
from . import users, hosts, groups, auth, upgrade
from ..resources import errors

@admin.after_request
def after_request(response):
    """ Logging after every request. """
    access_logger = logging.getLogger("app.access")
    ip = request.headers.get("X-Real-IP", request.remote_addr)
    access_logger.info(
        "%s [%s] %s %s %s %s %s %s %s",
        ip,
        dt.utcnow().strftime("%d/%b/%Y:%H:%M:%S.%f")[:-3],
        request.method,
        request.path,
        request.scheme,
        response.status,
        response.content_length,
        request.referrer,
        request.user_agent,
    )
    return response
