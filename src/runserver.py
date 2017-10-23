#!/usr/bin/env python3

import os
#import sys

import argparse

env_prepend = 'PASSWD_INTERFACE_'

parser = argparse.ArgumentParser()
parser.add_argument(
    '-c', '--config-file', dest='CONF_FILE', help='base config file location')
parser.add_argument(
    '-o', '--config-override', dest='CONF_OVERRIDE_FILE', help='config override file')
parser.add_argument(
    '-d', '--debug', dest='DEBUG', action='store_true',
    default=False, help='run the script in debug mode')
parser.add_argument(
    '-r', '--redis', dest='REDIS_HOST', help='max allowed percent change')

args = parser.parse_args()

for key, val in args.__dict__.items():
    if val:
        os.environ[env_prepend + key] = str(val)

from application import passwd_if

passwd_if.common.init_json_logging(passwd_if.app.config['logging_conf'], passwd_if.common.DEBUG)
passwd_if.app.run('0.0.0.0', debug=True)
