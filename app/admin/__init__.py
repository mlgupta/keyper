''' Init admin '''
from flask import Blueprint

admin = Blueprint('admin', __name__)

from . import users, hosts, groups, auth
from ..resources import errors
