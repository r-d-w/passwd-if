#!/usr/bin/evn python3
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


import logging
from time import time
from datetime import datetime


from redis import StrictRedis
from flask import Flask, request, session, jsonify, redirect, url_for, render_template


from .password_interface import common
from .password_interface.classes import (LDAPConnector, RedisTokens, Emailer, PasswdApiError,
                                         Session, PasswordChecker, LDAPConnectorError)


app = Flask(__name__)
REDIS = StrictRedis(host=common.REDIS_HOST)
app.config.update(common.CONF_DICT)
app.config['SESSION_REDIS'] = REDIS
if common.DEBUG:
    app.logger.setLevel('DEBUG')
logger = logging.getLogger(__name__)
LDAP = LDAPConnector(app.config['LDAP'])
TOKEN = RedisTokens({'redis': REDIS})
EMAIL = Emailer(app.config['EMAIL'])
PC = PasswordChecker(app.config['PASS_CHECK'], REDIS)
Session(app)


@app.errorhandler(PasswdApiError)
def error_handler(exc):
    """Catches PasswdApiErrors and forms a response for the client"""
    logger.error('%s: %s', exc.error_msg, exc.error_detail)
    resp = jsonify({'error': exc.error_msg, 'error_detail': exc.error_detail})
    resp.status_code = exc.status_code
    return resp

@app.before_request
def authz_request():
    """Authorizes the current request"""
    auth = request.authorization
    if request.endpoint in app.config['INSECURE_VIEWS']:
        return
    if not auth and not session.get('username'):
        return redirect(url_for('login', redirect=request.endpoint))
    elif hasattr(auth, 'username') and LDAP.auth_user(auth.username, auth.password):
        return
    elif session.get('username'):
        return
    raise PasswdApiError('Not Authorized', status_code=401)

@app.route('/authenticate', methods=['GET', 'POST'])
def authenticate():
    """/authenticate route: GET, POST

    POST - form body
        redirect (str) opt - where to land after auth. defaults resetPasswd
        username (str) req - the username you are authing
        password (str) req - password for the user

    GET - query string
        token (str) req - your reset token
    """
    if request.method == 'POST':
        destination = request.form.get('redirect', 'resetPasswd')
        username = request.form['username']
        password = request.form['password']
        if not LDAP.auth_user(username, password):
            session.set_message({'msg_type': 'danger', 'msg':'Username/Password Incorrect'})
            return redirect(url_for('login'))
    elif request.method == 'GET':
        destination = 'resetPasswd'
        token = request.args.get('token')
        username = TOKEN.get_token(token)
        if username:
            session['token_reset'] = 1
            TOKEN.delete_token(token)
        else:
            session.set_message({'msg_type': 'danger', 'msg': 'Token not found'})
            return redirect(url_for('login'))
    user_ldap_obj = LDAP.find_ldap_user(username)
    user_groups = LDAP.get_entry_groups(user_ldap_obj)
    session['username'] = username
    session['session_start'] = int(time())
    session['user_groups'] = user_groups
    return redirect(url_for(destination))

@app.route('/emailReset', methods=['POST'])
def emailReset():
    """/emailReset route: POST

    POST - form body
        users (list of str) req - list of users to kick off email reset for
    """
    if not check_admin():
        PasswdApiError('Not Authorized. This route only for admins')
    users = request.form.getlist('user')
    message = 'reset emails sent to: '
    for user in users:
        username, email = user.split(':')
        token = TOKEN.create_token(username)
        EMAIL.send_email(
            email, [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), session['username']],
            [url_for('authenticate', token=token, _external=True)])
        message += '{}, '.format(username)
    session.set_message({'msg_type': 'success', 'msg': message[:-2]})
    return redirect(url_for('resetPasswd'))

@app.route('/login')
def login():
    """/login route: GET"""
    _redirect = request.args.get('redirect')
    return render_template('login.html', redirect=_redirect)

@app.route('/resetPasswd')
def resetPasswd():
    """/resetPasswd route: GET"""
    un_attr = app.config['LDAP']['username_attribute']
    if check_token_reset():
        return render_template(
            'resetPasswd.html', token_reset=True, requirements=PC)
    elif check_admin():
        users = {
            '{}:{}'.format(
                user[un_attr].value, user[app.config['email_attribute']].value): user[
                    app.config['name_attribute']].value
            for user in LDAP.search(
                '(&({}=*)({}=*)(!(userAccountControl=514)))'.format(
                    app.config['LDAP']['username_attribute'], app.config['email_attribute']),
                attributes=[
                    app.config['email_attribute'], app.config['name_attribute'],
                    app.config['LDAP']['username_attribute']])}
        return render_template(
            'resetPasswd.html', admin=True, users=users, requirements=PC)
    else:
        return render_template('resetPasswd.html', requirements=PC)

@app.route('/session_info')
def session_info():
    """/session_info route: GET"""
    return jsonify(dict(session))

@app.route('/setUserPassword', methods=['POST'])
def setUserPassword():
    """/setUserPassword route: POST

    POST - form body
        current_password (str) opt - users current password
        username (str) opt - username of the user
        new_password (str) req - new password
    """
    logger.debug('setUserPassword: %s', request.form)
    is_admin = check_admin()
    is_token_reset = check_token_reset()
    current_password = request.form.get('current_password')
    if is_admin and not is_token_reset:
        username = request.form.get('username', session['username'])
    else:
        username = session['username']
    if current_password and not LDAP.auth_user(username, request.form['current_password']):
        session.set_message({'msg_type': 'error', 'msg': 'Your current password is incorrect'})
        return redirect(url_for('resetPasswd'))
    new_pass = request.form['new_password']
    check_ret = PC.check_password(username, new_pass)
    if not check_ret[0]:
        session.set_message({'msg_type': 'error', 'msg': check_ret[1]})
        return redirect(url_for('resetPasswd'))
    try:
        if LDAP.set_user_password(username, new_pass):
            message = {'msg_type': 'success', 'msg': 'Password change successful'}
            if current_password or is_token_reset:
                session.clear()
                session.set_message(message)
                PC.add_password(username, new_pass)
                return redirect(url_for('login'))
            else:
                PC.add_password(username, new_pass)
                session.set_message(message)
                return redirect(url_for('resetPasswd'))
        else:
            session.set_message({'msg_type': 'error', 'msg': 'Password change failed'})
            return redirect(url_for('resetPasswd'))
    except LDAPConnectorError as exc:
        session.set_message({'msg_type': 'error', 'msg': exc.error})

@app.route('/logout')
def logout():
    """/logout route: GET"""
    session.clear()
    session.set_message({'msg_type': 'success', 'msg': 'Logout Successful'})
    return redirect(url_for('login'))

def check_admin():
    """Verifies if the authenticated user is in the admin group"""
    if app.config['admin_group'] in session['user_groups']:
        return True

def check_token_reset():
    """Verifies if the token_reset was set for this session"""
    return session.get('token_reset')


if __name__ == '__main__':
    common.init_json_logging(app.config['logging_conf'], common.DEBUG)
    app.run(debug=True)
