''' init public '''
from flask import Blueprint

public = Blueprint('public', __name__)

from . import authkeys
from ..resources import errors
