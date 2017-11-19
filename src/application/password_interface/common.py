# Copyright 2017 Ryan David Williams
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Contains configuration and other common code"""

import os
import sys
import json
from base64 import b64decode
from binascii import Error
from importlib import import_module
from logging.config import dictConfig


env_prepend = 'PASSWD_INTERFACE_'

DEFAULT_CONF_FILE = '/etc/password_interface/passwd_interface_conf.json'
DEFAULT_LOGGER_NAME = 'passwd_interface'
DEFAULT_REDIS_HOST = 'passwd-if-redis-server'
DEFAULT_PLUGIN_DIR = '/etc/password_interface/plugins'
DEFAULT_SECRETS_DIR = '/secrets'

CONF_FILE = os.environ.get(env_prepend + 'CONF_FILE', DEFAULT_CONF_FILE)
CONF_OVERRIDE_FILE = os.environ.get(env_prepend + 'CONF_OVERRIDE_FILE')
LOGGER_NAME = os.environ.get(env_prepend + 'LOGGER_NAME', DEFAULT_LOGGER_NAME)
DEBUG = os.environ.get(env_prepend + 'DEBUG', False)
REDIS_HOST = os.environ.get(env_prepend + 'REDIS_HOST', DEFAULT_REDIS_HOST)
SECRETS_DIR = os.environ.get(env_prepend + 'SECRETS_DIR', DEFAULT_SECRETS_DIR)

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
    with open(CONF_FILE) as _fh:
        conf = json.load(_fh)
    if CONF_OVERRIDE_FILE:
        with open(CONF_OVERRIDE_FILE) as _fh:
            override = json.load(_fh)
        conf.update(override)
    conf = replace_conf_nulls(conf)
    try:
        conf['SECRET_KEY'] = b64decode(conf['SECRET_KEY'])
    except Error:
        print('Secret key not base64 encoded')
    except TypeError:
        print('Secret key is blank')
    return conf

def replace_conf_nulls(_dict, context=None):
    """Transverses a config dictionary and attempts to replace key with a None value
    with one retrived from an environment variable or a flat file in a secrets directory
    """
    if not context:
        context = env_prepend + 'SCONF'
    for key, val in _dict.items():
        local_context = '{}__{}'.format(context, key.upper())
        if isinstance(val, dict):
            val = replace_conf_nulls(val, local_context)
        elif val is None:
            if os.environ.get(local_context):
                _dict[key] = os.environ[local_context]
            elif os.path.isfile(os.path.join(SECRETS_DIR, local_context)):
                with open(os.path.join(SECRETS_DIR, local_context)) as _fh:
                    _dict[key] = _fh.read().strip()
    return _dict

def load_plugins(conf):
    """loads all plugins"""
    plugins = {}
    sys.path.insert(0, conf.pop('plugin_directory', DEFAULT_PLUGIN_DIR))
    for p_type in conf:
        plugins[p_type] = {}
        for plugin, settings in conf[p_type].items():
            mod = import_module(settings['handler']['module'])
            cls = getattr(mod, settings['handler']['class'])
            plugins[p_type][plugin] = cls(settings['config'])
    del sys.path[0]
    return plugins

CONF_DICT = load_conf_file()
