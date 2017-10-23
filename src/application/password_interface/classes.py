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

import re
import os
import json
import logging
import smtplib
import binascii
from email.mime.text import MIMEText
from importlib import import_module
from collections import OrderedDict


import ldap3
from slackclient import SlackClient
from flask_session import Session as _Session


from . import common


RESET_TOKEN_KEY = 'resetToken'  #default key prepended to all redis reset tokens
RESET_TOKEN_TIMEOUT = 60*60*24      #default # of seconds before reset token timesout
RESET_TOKEN_BYTES = 64            #default number of bytes used to generate token
LDAP_TYPE_TO_EXTEND_MAP = {'active_directory': 'microsoft', 'openldap': 'standard'}
SMTP_PORT = 25


logger = logging.getLogger(__name__)
if common.DEBUG:
    logger.setLevel('DEBUG')


class Session(_Session):
    """adds some functionality to the flask-session Session class"""

    def init_app(self, app):
        """replaces the flask_session.Session.init_app with one that injects extra
        additional methods for handling user message"""
        session = self._get_interface(app)
        #define functions to bind to the Session object
        def consume_message(self):
            """removes the message from the session and returns it"""
            msg = self.get('message')
            self['message'] = None
            logger.debug('consume message: %s', msg)
            return msg
        def set_message(self, msg):
            """sets the sesion message"""
            logger.debug('set message: %s', msg)
            self['message'] = json.dumps(msg)
        def check_message(self):
            """checks if a message is set"""
            logger.debug('check_message: %s', bool(self.get('message')))
            return bool(self.get('message'))
        #inject them
        setattr(session.session_class, 'consume_message', consume_message)
        setattr(session.session_class, 'set_message', set_message)
        setattr(session.session_class, 'check_message', check_message)
        app.session_interface = session


class RedisTokens(object):
    """Used to manipulate tokens for password reset operations"""

    def __init__(self, conf):
        """initializes RedisTokens object.

        Args:
            conf: dict - {
                'redis': <StrictRedis>,                         #req
                'token_key': 'resetToken',                      #opt
                'token_lifetime': 86400                         #opt - sec before token expire
            }
        """
        self._conf = conf
        self._token_key = conf.get('token_key', RESET_TOKEN_KEY)
        self._token_lifetime = conf.get('token_lifetime', RESET_TOKEN_TIMEOUT)
        try:
            self._redis = conf['redis']
        except KeyError as exc:
            logger.error('Missing required configuration key: %s', exc)
            raise exc

    def _make_token_key(self, token):
        return '{}:{}'.format(self._token_key, token)

    def get_token(self, token):
        """retreives the requested token from the store"""
        result = self._redis.get(self._make_token_key(token))
        if result:
            return result.decode('utf-8')

    def create_token(self, username):
        """creates a token with user information attached"""
        token = binascii.hexlify(os.urandom(RESET_TOKEN_BYTES)).decode()
        rkey = self._make_token_key(token)
        if self._redis.set(rkey, username.encode('utf-8'), self._token_lifetime):
            return token

    def delete_token(self, token):
        """deletes the requested token"""
        rkey = self._make_token_key(token)
        return bool(self._redis.delete(rkey) != 0)


class LDAPConnector(object):
    """Contains all LDAP operations"""

    def __init__(self, conf):
        """initalizes LDAPConnector object.

        Args:
            conf: dict - {
                'host': 'dc1.example.com',                      #req
                'port': 389,                                    #opt - needed only for odd ports
                'search_base': 'dc=example,dc=com',             #req
                'bind_user': 'uid=manager,dc=example,dc=com',   #req
                'bind_passwd': 'ReallyGoodPass1',               #req
                'username_attribute': 'sAMAccountName',         #req
                'start_tls': False,                             #opt - exclusive of use_ssl
                'use_ssl': False,                               #opt - exclusive of start_tls
                'ldap_type': 'openldap',                        #opt - active_directory | openldap
                'member_attr': 'member'                         #opt
            }
        """
        self._conf = conf
        try:
            self._server = ldap3.Server(
                conf['host'], port=conf.get('port'), use_ssl=conf.get('use_ssl'))
            self._ldap = self._make_connection()
            self._search_base = conf['search_base']
            self._start_tls = conf.get('start_tls')
            self._ldap_type = LDAP_TYPE_TO_EXTEND_MAP[self._conf.get('ldap_type', 'openldap')]
            self._member_attr = conf.get('member_attr', 'member')
        except KeyError as exc:
            logger.error('LDAPConnector missing required configuration key: %s', exc)
            raise exc

    def _make_connection(self, user=None, passwd=None):
        """takes a user name and password to check"""
        if not user and not passwd:
            user = self._conf['bind_user']
            passwd = self._conf['bind_passwd']
        logger.debug('making connection to LDAP server as user: %s', user)
        return ldap3.Connection(self._server, user=user, password=passwd)

    def _disconnect(self):
        """closes the connection"""
        logger.debug('disconnecting from LDAP server')
        self._ldap.unbind()

    def _get_all_groups(self):
        logger.debug('_get_all_groups')
        all_groups = self.search('(objectClass=group)', attributes=['member'])
        logger.debug('found %s groups', len(all_groups))
        group_dict = {group.entry_dn: group.member.values for group in all_groups}
        return group_dict

    def _recurse_groups(self, entry_dn, members_groups):
        if entry_dn not in members_groups:
            return list()
        else:
            entry_groups = members_groups[entry_dn]
            for group_dn in members_groups[entry_dn]:
                entry_groups.extend(self._recurse_groups(group_dn, members_groups))
            return entry_groups

    def get_entry_groups(self, entry):
        """take ldap object and returns a set of group dn's it belongs to recursively"""
        logger.debug('get_entry_groups')
        groups_members = self._get_all_groups()
        members_groups = {}
        for group_dn, members in groups_members.items():
            for member in members:
                members_groups[member] = members_groups.get(member, []) + [group_dn]
        entries_groups = set(self._recurse_groups(entry.entry_dn, members_groups))
        logger.debug(
            '%s is in the following groups: %s',
            getattr(entry, self._conf['username_attribute']), entries_groups)
        return sorted(list(entries_groups))

    def connect(self):
        """opens the connection, inits start_tls, and binds"""
        self._ldap.open()
        logger.debug('opening LDAP connection')
        if self._start_tls:
            logger.debug('init StartTLS')
            if not self._ldap.start_tls():
                raise LDAPConnectorError(
                    error='Unable to initiate StartTLS as configured', detail=self._ldap.result)
        if not self._ldap.bind():
            raise LDAPConnectorError(error='Unable to bind', detail=self._ldap.result)
        logger.debug('LDAP connection established')

    def search(self, ldap_filter, subtree=None, attributes=None):
        """Generic search function

        param ldap_filter: full ldap style search filter including the ()
        param subtree: the specific subtree you wish to search
        param attributes: attributes you want to retrieve with the requested records
        type attributes: list of strings
        returns list of ldap objects
        """
        logger.debug(
            'search ldap_filter: %s subtree: %s attributes: %s', ldap_filter, subtree, attributes)
        search_base = subtree + self._search_base if subtree else self._search_base
        logger.debug('search_base: %s', search_base)
        if not attributes:
            logger.debug('retrieving all attributes')
            attributes = ldap3.ALL_ATTRIBUTES
        self.connect()
        self._ldap.search(search_base, ldap_filter, attributes=attributes)
        entries = self._ldap.entries
        logger.debug('number of entries found: %s', len(entries))
        return entries

    def find_ldap_user(self, username):
        """finds a user in ldap based on username"""
        logger.debug('find_ldap_user username: %s', username)
        ldap_filter = '({}={})'.format(self._conf['username_attribute'], username)
        try:
            return self.search(ldap_filter)[0]
        except IndexError:
            logger.info('Username not found.')
            return None
        finally:
            self._disconnect()

    def get_all_users(self, attributes=None):
        """gets all entries containing the username_attribute"""
        logger.debug('get_all_user')
        ldap_filter = '({}=*)'.format(self._conf['username_attribute'])
        results = self.search(ldap_filter, attributes=attributes)
        self._disconnect()
        return results

    def auth_user(self, username, password):
        """take a user and passwords and tests authentication using
        a bind to the AD. returns true if successful"""
        logger.debug('auth_user username: %s')
        config = self._conf.copy()
        try:
            user_dn = self.find_ldap_user(username).entry_dn
        except AttributeError:
            logger.debug('Username not found')
            return False
        logger.debug('dn found for user: %s', user_dn)
        config.update({'bind_user': user_dn, 'bind_passwd': password})
        try:
            con = LDAPConnector(config)
            con.connect()
            logger.debug('User auth successful')
            return True
        except:
            logger.debug('User auth failed')
            return False

    def set_user_password(self, username, new_pass, current_password=None):
        """sets the users password to the supplied string, returns True for successful and
        the error message if its not"""
        logger.debug('set_user_password username: %s', username)
        passwdf = getattr(self._ldap.extend, self._ldap_type).modify_password
        try:
            user_dn = self.find_ldap_user(username).entry_dn
            logger.debug('dn found for user: %s', user_dn)
        except AttributeError:
            raise LDAPConnectorError(error='username not found: {}'.format(username))
        self.connect()
        resp = passwdf(user_dn, new_pass, current_password)
        logger.debug('modify_password_response: %s', resp)
        return resp


class Emailer(object):
    """Wrapper around emailing functions."""

    def __init__(self, conf):
        """Initializes Emailer object.

        Args:
            conf: dict - {
                smtp_host: 'smtp.example.com',                    #req
                smtp_port: 25,                                    #opt
                smtp_user: 'admin',                               #opt
                smtp_pass: 'pass',                                #opt
                smtp_starttls: True,                              #opt
                email_from: 'admin@example.com',                  #req
                email_subject_template: 'SomeSubject',            #req
                email_message_template: 'SomeMessage'             #req
            }
        """
        self._conf = conf
        try:
            self._smtp = smtplib.SMTP()
            self._smtp_host = conf['smtp_host']
            self._smtp_port = conf.get('smtp_port', SMTP_PORT)
            self._subject = conf['email_subject_template']
            self._message = conf['email_message_template']
            self._from = conf['email_from']
        except KeyError as exc:
            raise EmailerException('Emailer configuration dict requires: {}'.format(exc))

    def _connect(self):
        self._smtp.connect(self._smtp_host, self._smtp_port)
        if self._conf.get('smtp_starttls'):
            self._smtp.starttls()
        if self._conf.get('smtp_user') and self._conf.get('smtp_pass'):
            self._smtp.login(self._conf['smtp_user'], self._conf['smtp_pass'])

    def send_email(self, email_to, subject_subs=None, message_subs=None):
        """General email sending function.

        param email_to: email address of the intended receipent
        param subject_subs: list containing subject line subs for template
        type subject_subs: list of strings
        param message_subs: list containing message subs for template
        type message_subs: list of strings
        """
        try:
            self._connect()
            msg = MIMEText(self._message.format(*message_subs))
            msg['Subject'] = self._subject.format(*subject_subs)
            msg['From'] = self._from
            msg['To'] = email_to
            self._smtp.sendmail(
                self._from, email_to, msg.as_string())
        except IndexError:
            raise EmailerException(
                'Check that you are providing the correct number of arguments for any templates')
        finally:
            self._smtp.quit()


class SlackAPI(object):
    """Used for interacting with Slack"""

    def __init__(self, conf):
        """initalizes SlackAPI object.

        Args:
            conf: dict - {
                'web_api_token': 'xoxp-XXXXXXXXXXXXXXXXXX',     #req
                'search_field': 'email'                         #opt - defaults 'display_name'
            }
        """
        self._conf = conf
        try:
            self._slack = SlackClient(conf['web_api_token'])
            self._search_field = conf.get('search_field', 'display_name')
        except KeyError as exc:
            raise SlackAPIError('SlackAPI configuration dict requires: {}'.format(exc))

    def get_userid(self, query, field=None):
        """uses the configured field and supplied value to search for and returns slack userid"""
        users = self._slack.api_call('users.list')['members']
        if not field:
            field = self._search_field
        for user in users:
            if field in user:
                if user[field] == query:
                    return user['id']
            if field in user['profile']:
                if user['profile'][field] == query:
                    return user['id']
 
    def send_message(self, uid, message):
        """send a message to the specified user"""
        self._slack.api_call('chat.postMessage', channel=uid, text=message)


class PasswordChecker(object):
    """Used to verify if a password meets the configured requirements"""

    DEFAULT_BLOWFISH_SALT = 8
    """Used to provide the blowfish salt generator its log_roungds param. increase for security
    but will make every password reset be slower"""

    DEFAULT_POLICY = {10: {'expires': 180}}
    """Used when no policies are provided in the conf dict"""

    DEFAULT_REDIS_PASSWORD_PREFIX = 'password'
    """Used as a prefix for the redis key user passwords are stored in"""

    DEFAULT_MAX_HISTORY = 24

    CHARACTER_CLASSES = {
        'symbol': r'.*[^\w\d].*',
        'number': r'.*[\d].*',
        'upper': r'.*[A-Z].*',
        'lower': r'.*[a-z].*'
    }

    def __init__(self, conf, redis=None):
        """Initializes the PasswordChecker using a config dict

        Args:
            conf: dict - {
                track_usage: (bool, optional, True) - keep and track history of password,
                max_history: (int, optional, DEFAULT_MAX_HISTORY) - number of previous hashes to
                    keep per user,
                blowfish_salt: (int, optional, DEFAULT_BLOWFISH_SALT) - overide default,
                redis_prefix: (str, optional, DEFAULT_REDIS_PASSWORD_PREFIX) - overide default,
                policies: {
                    (int): { - Min num of chars for this policy to apply
                        'expires': (int) - in days, never is not an option,
                        'unicode': (bool, optional, True) - support unicode chars,
                        'char_classes': (int, optional, 4) - number of classes of characters
                            required, lower, upper, number, symbol
                    }
                }
            redis: (obj:StrictRedis, optional) - optional only if storing history

        Examples:
            conf = {
                'track_usage': True,
                'max_history': 24,
                'policies': {
                    10: {'expires': 180},
                    25: {'expires': 720, 'char_classes': 1}}}
            REDIS = StrictRedis()
            pc = PasswordChecker(conf, REDIS)
        """
        self._conf = conf
        if not redis:
            from redis import StrictRedis
            self._redis = StrictRedis()
        else:
            self._redis = redis
        self._track = conf.get('track_usage', True)
        if self._track:
            self._bcrypt = import_module('bcrypt')
        self._redis_prefix = self._conf.get('redis_prefix', self.DEFAULT_REDIS_PASSWORD_PREFIX)
        self._bcrypt_salt = self._conf.get('blowfish_salt', self.DEFAULT_BLOWFISH_SALT)
        self.max_history = self._conf.get('max_history', self.DEFAULT_MAX_HISTORY)
        self.policies = OrderedDict(sorted(
            {
                int(key): val
                for key, val in conf.get('policies', self.DEFAULT_POLICY).items()}.items(),
            key=lambda x: x[0]))

    def _create_bcrypt_hash(self, password):
        return self._bcrypt.hashpw(
            password.encode('UTF-8'), self._bcrypt.gensalt(self._bcrypt_salt))

    def _create_key(self, username):
        return ':'.join((self._redis_prefix, username))

    def _check_char_classes(self, password):
        """checks for all character classes, returns a list of checks that failed"""
        return [key for key, val in self.CHARACTER_CLASSES.items() if not re.match(val, password)]

    def _check_history(self, username, password):
        old_passwords = self._redis.lrange(self._create_key(username), 0, self.max_history - 1)
        for old_password in old_passwords:
            if self._bcrypt.hashpw(password.encode('UTF-8'), old_password) == old_password:
                return False
        return True

    def add_password(self, username, password):
        """addes a password hash for the user to the history db"""
        if not self._track:
            return
        key = self._create_key(username)
        llen = self._redis.lpush(key, self._create_bcrypt_hash(password))
        if llen > self.max_history:
            self._redis.ltrim(key, 0, self.max_history - 1)

    def check_password(self, username, password):
        """takes a password returns a tuple with status and an error message"""
        num_char_classes = len(self.CHARACTER_CLASSES)
        for min_len in reversed(self.policies):
            if len(password) >= min_len:
                req_char_classes = self.policies[min_len].get('char_classes', num_char_classes)
                failures = self._check_char_classes(password)
                if len(failures) > num_char_classes - req_char_classes:
                    return (
                        False, 'You are required to have {} character classes you are missing:'
                        ' {}'.format(req_char_classes, ', '.join(failures)))
                else:
                    if self._track and not self._check_history(username, password):
                        return (
                            False,
                            'You cannot reuse the last {} passwords'.format(self.max_history))
                    return(True, '')
        return (
            False,
            'Your password needs to be at least {} characters long'.format(
                list(self.policies)[0]))


class LDAPConnectorError(Exception):
    """logs exceptions at various log levels"""

    def __init__(self, error, detail=None, *args, **kwargs):
        self.error = error
        self.detail = detail
        logger.error('%s error msg: %s', self.__class__.__name__, self.error)
        logger.debug('%s error detail msg: %s', self.__class__, self.detail)
        super(LDAPConnectorError, self).__init__('{} : {}'.format(error, detail), *args, **kwargs)


class SlackAPIError(Exception):
    """logs exceptions at various log levels"""

    def __init__(self, error, detail=None, *args, **kwargs):
        self.error = error
        self.detail = detail
        logger.error('%s error msg: %s', self.__class__.__name__, self.error)
        logger.debug('%s error detail msg: %s', self.__class__, self.detail)
        super(SlackAPIError, self).__init__('{} : {}'.format(error, detail), *args, **kwargs)


class PasswdApiError(Exception):
    """generalized Passwd API Error"""

    def __init__(self, error_msg, error_detail=None, status_code=500):
        self.error_msg = error_msg
        self.error_detail = error_detail
        self.status_code = status_code
        super(PasswdApiError, self).__init__(error_msg)


class EmailerException(Exception):
    """generic EmailerException"""
    pass
