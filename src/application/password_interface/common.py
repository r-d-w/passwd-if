"""
Copyright 2017 Ryan David Williams

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import os
import json
from base64 import b64decode
from logging.config import dictConfig


env_prepend = 'PASSWD_INTERFACE_'
secrets = {
    'SECRET_KEY': os.environ.get('FLASK_SECRET_KEY'),
    'EMAIL': {'smtp_pass': os.environ.get('EMAIL_SMTP_PASS')},
    'LDAP': {'bind_passwd': os.environ.get('LDAP_BIND_PASS')}}

DEFAULT_CONF_FILE = '/etc/password_interface/passwd_interface_conf.json'
DEFAULT_LOGGER_NAME = 'passwd_interface'
DEFAULT_REDIS_HOST = 'passwd_if_redis_server'

CONF_FILE = os.environ.get(env_prepend + 'CONF_FILE', DEFAULT_CONF_FILE) 
CONF_OVERRIDE_FILE = os.environ.get(env_prepend + 'CONF_OVERRIDE_FILE')
LOGGER_NAME = os.environ.get(env_prepend + 'LOGGER_NAME', DEFAULT_LOGGER_NAME)
DEBUG = os.environ.get(env_prepend + 'DEBUG', False)
REDIS_HOST = os.environ.get(env_prepend + 'REDIS_HOST', DEFAULT_REDIS_HOST)

def init_json_logging(conf, debug=None):
    """Initializes the global logging stuffz from a logging dictionary.

    Args:
        conf: logging config dictionary
        debug: enables debug logging.
    """
    if debug:
        conf['handlers']['console']['level'] = 'DEBUG'
    dictConfig(conf)

def load_conf_file():
    """Loads the configuration file"""
    with open(CONF_FILE) as fh:
        conf = json.load(fh)
    if CONF_OVERRIDE_FILE:
        with open(CONF_OVERRIDE_FILE) as fh:
            override = json.load(fh)
        conf.update(override)
    for key, val in secrets.items():
        if isinstance(val, dict) and None not in val.values():
            conf[key].update(val)
        elif isinstance(val, str):
            conf[key] = val
    conf['SECRET_KEY'] = b64decode(conf['SECRET_KEY'])
    return conf

CONF_DICT = load_conf_file()
