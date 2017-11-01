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
"""passwd-if plugins"""

# standard library imports
import logging
import smtplib
from datetime import datetime
from email.mime.text import MIMEText

# third party imports
from slackclient import SlackClient

# Globals
SMTP_PORT = 25


logger = logging.getLogger(__name__)


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

    def send_token(self, user_id, admin_id, token):
        """Implements send_token method for token plugin"""
        self.send_email(user_id, [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), admin_id], [token])


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

    def send_token(self, user_id, admin_id, token):
        """Implements send_token method for token plugin"""
        uid = self.get_userid(user_id)
        message = (
            '{} requested a password reset token on your behalf.\n'
            'To reset your password please follow this link: <{}>'.format(admin_id, token))
        self.send_message(uid, message)


class EmailerException(Exception):
    """generic EmailerException"""
    pass


class SlackAPIError(Exception):
    """logs exceptions at various log levels"""

    def __init__(self, error, detail=None, *args, **kwargs):
        self.error = error
        self.detail = detail
        logger.error('%s error msg: %s', self.__class__.__name__, self.error)
        logger.debug('%s error detail msg: %s', self.__class__, self.detail)
        super(SlackAPIError, self).__init__('{} : {}'.format(error, detail), *args, **kwargs)
