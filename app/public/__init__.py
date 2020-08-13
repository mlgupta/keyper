''' init public '''
from flask import Blueprint

public = Blueprint('public', __name__)

import logging
from datetime import datetime as dt
from flask import current_app as app
from flask import request
from . import authkeys
from ..resources import errors

@public.after_request
def after_request(response):
    """ Logging after every request. """
    access_logger = logging.getLogger("app.access")
    access_logger.info(
        "%s [%s] %s %s %s %s %s %s %s",
        request.remote_addr,
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
