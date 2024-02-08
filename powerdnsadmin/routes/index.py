import os
# import re
import json
# import io
# import base64
import traceback
import datetime
# import ipaddress
# import base64
import string
from zxcvbn import zxcvbn
# from distutils.util import strtobool
from yaml import Loader, load
from flask import Blueprint, render_template, make_response, url_for, current_app, g, session, request, redirect, abort, jsonify
from flask_login import login_user, logout_user, login_required, current_user

from .base import captcha, csrf, login_manager
# from ..lib import utils
# from ..decorators import dyndns_login_required
# from ..models.base import db
from ..models.user import User, Anonymous
from ..models.role import Role
from ..models.account import Account

from ..models.setting import Setting
from ..models.history import History

from ..services.sudis import SUDIS

sudis = None

index_bp = Blueprint('index',
                     __name__,
                     template_folder='templates',
                     url_prefix='/')


@index_bp.before_app_first_request
def register_modules():
    global sudis
    sudis = SUDIS()


@index_bp.before_request
def before_request():
    # Check if user is anonymous
    g.user = current_user
    login_manager.anonymous_user = Anonymous

    # Check site is in maintenance mode
    maintenance = Setting().get('maintenance')
    if maintenance and current_user.is_authenticated and current_user.role.name not in [
        'Administrator', 'Operator'
    ]:
        return render_template('maintenance.html.jinja')

    # Manage session timeout
    session.permanent = True
    current_app.permanent_session_lifetime = datetime.timedelta(
        minutes=int(Setting().get('session_timeout')))
    session.modified = True


@index_bp.get('/lang')
@login_required
def set_lang():
    # lang_code = request.args.get('lang')
    lang_code = session.get("lang")
    if lang_code == "en":
        session["lang"] = "ru"
    elif lang_code == "ru":
        session["lang"] = "en"
    else:
        session["lang"] = "ru"
    return redirect(request.args.get("current_page"))

@index_bp.get("/toggle-theme")
@login_required
def toggle_theme():
    current_theme = session.get("theme")
    if current_theme == "dark":
        session["theme"] = "light"
    else:
        session["theme"] = "dark"

    return redirect(request.args.get("current_page"))

@index_bp.route('/', methods=['GET'])
@login_required
def index():
    return redirect(url_for('dashboard.dashboard'))


@index_bp.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "ok"})


@index_bp.route('/login', methods=['GET', 'POST'])
def login():
    # SAML_ENABLED = current_app.config.get('SAML_ENABLED', False)
    VERSION = current_app.config.get("VERSION", None)

    if g.user is not None and current_user.is_authenticated:
        return redirect(url_for('dashboard.dashboard'))

    if request.method == 'GET':
        return render_template('login.html.jinja', version=VERSION)
    elif request.method == 'POST':
        # process Local-DB authentication
        username = request.form['username']
        password = request.form['password']
        # otp_token = request.form.get('otptoken')
        auth_method = request.form.get('auth_method', 'LOCAL')
        # session['authentication_type'] = 'LDAP' if auth_method != 'LOCAL' else 'LOCAL'
        session['authentication_type'] = 'LOCAL'
        remember_me = True # if 'remember' in request.form else False

        via_sudis = request.form.get("via_sudis")
        
        if via_sudis == "on":
            return redirect(url_for("index.sudis_login"))
        if auth_method == 'LOCAL' and not Setting().get('local_db_enabled'):
            return render_template(
                'login.html.jinja',
                # saml_enabled=SAML_ENABLED,
                version=VERSION,
                error='Local authentication is disabled')

        user = User(username=username,
                    password=password,
                    plain_text_password=password)

        try:
            # if Setting().get('verify_user_email') and user.email and not user.confirmed:
            #     return render_template(
            #         'login.html.jinja',
            #         saml_enabled=SAML_ENABLED,
            #         version=VERSION,
            #         error='Please confirm your email address first')

            auth = user.is_validate(method=auth_method,
                                    src_ip=request.remote_addr)
            if auth == False:
                signin_history(user.username, auth_method, False)
                return render_template('login.html.jinja',
                                    #    saml_enabled=SAML_ENABLED,
                                       version=VERSION,
                                       error='Invalid credentials')
        except Exception as e:
            current_app.logger.error(
                "Cannot authenticate user. Error: {}".format(e))
            current_app.logger.debug(traceback.format_exc())
            return render_template('login.html.jinja',
                                #    saml_enabled=SAML_ENABLED,
                                   version=VERSION,
                                   error=e)
        return authenticate_user(user, auth_method, remember_me)



def clear_session():
    session.pop('user_id', None)
    logout_user()


def signin_history(username, authenticator, success):
    # Get user ip address
    if request.headers.getlist("X-Forwarded-For"):
        request_ip = request.headers.getlist("X-Forwarded-For")[0]
        request_ip = request_ip.split(',')[0]
    else:
        request_ip = request.remote_addr

    # Write log
    if success:
        str_success = 'succeeded'
        current_app.logger.info(
            "User {} authenticated successfully via {} from {}".format(
                username, authenticator, request_ip))
    else:
        str_success = 'failed'
        current_app.logger.warning(
            "User {} failed to authenticate via {} from {}".format(
                username, authenticator, request_ip))

    # Write history
    History(msg='User {} authentication {}'.format(username, str_success),
            detail=json.dumps({
                'username': username,
                'authenticator': authenticator,
                'ip_address': request_ip,
                'success': 1 if success else 0
            }),
            created_by='System').add()


# # Get a list of Azure security groups the user is a member of
# def get_azure_groups(uri):
#     azure_info = azure.get(uri).text
#     current_app.logger.info('Azure groups returned: ' + azure_info)
#     grouplookup = json.loads(azure_info)
#     if "value" in grouplookup:
#         mygroups = grouplookup["value"]
#         # If "@odata.nextLink" exists in the results, we need to get more groups
#         if "@odata.nextLink" in grouplookup:
#             # The additional groups are added to the existing array
#             mygroups.extend(get_azure_groups(grouplookup["@odata.nextLink"]))
#     else:
#         mygroups = []
#     return mygroups


def authenticate_user(user, authenticator, remember=False):
    login_user(user, remember=remember)
    signin_history(user.username, authenticator, True)
    # if Setting().get('otp_force') and Setting().get('otp_field_enabled') and not user.otp_secret \
    #         and session['authentication_type'] not in ['OAuth']:
    #     user.update_profile(enable_otp=True)
    #     user_id = current_user.id
    #     prepare_welcome_user(user_id)
    #     return redirect(url_for('index.welcome'))
    return redirect(url_for('index.login'))


# # Prepare user to enter /welcome screen, otherwise they won't have permission to do so
# def prepare_welcome_user(user_id):
#     logout_user()
#     session['welcome_user_id'] = user_id


@index_bp.route('/logout')
def logout():
    if current_app.config.get(
            'SAML_ENABLED'
    ) and 'samlSessionIndex' in session and current_app.config.get('SAML_LOGOUT'):
        req = sudis.prepare_flask_request(request)
        auth = sudis.init_saml_auth(req)
        if current_app.config.get('SAML_LOGOUT_URL'):
            return redirect(
                auth.logout(
                    name_id_format=
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                    return_to=current_app.config.get('SAML_LOGOUT_URL'),
                    session_index=session['samlSessionIndex'],
                    name_id=session['samlNameId']))
        return redirect(
            auth.logout(
                name_id_format=
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                session_index=session['samlSessionIndex'],
                name_id=session['samlNameId']))

    redirect_uri = url_for('index.login')
    # oidc_logout = Setting().get('oidc_oauth_logout_url')

    # if 'oidc_token' in session and oidc_logout:
    #     redirect_uri = "{}?redirect_uri={}".format(
    #         oidc_logout, url_for('index.login', _external=True))

    # Clean cookies and flask session
    clear_session()

    # If remote user authentication is enabled and a logout URL is configured for it,
    # redirect users to that instead
    # remote_user_logout_url = current_app.config.get('REMOTE_USER_LOGOUT_URL')
    # if current_app.config.get('REMOTE_USER_ENABLED') and remote_user_logout_url:
    #     current_app.logger.debug(
    #         'Redirecting remote user "{0}" to logout URL {1}'
    #         .format(current_user.username, remote_user_logout_url))
    #     # Warning: if REMOTE_USER environment variable is still set and not cleared by
    #     # some external module, not defining a custom logout URL will trigger a loop
    #     # that will just log the user back in right after logging out
    #     res = make_response(redirect(remote_user_logout_url.strip()))

    #     # Remove any custom cookies the remote authentication mechanism may use
    #     # (e.g.: MOD_AUTH_CAS and MOD_AUTH_CAS_S)
    #     remote_cookies = current_app.config.get('REMOTE_USER_COOKIES')
    #     for r_cookie_name in utils.ensure_list(remote_cookies):
    #         res.delete_cookie(r_cookie_name)

    #     return res

    return redirect(redirect_uri)


def password_policy_check(user, password):
    def check_policy(chars, user_password, setting):
        setting_as_int = int(Setting().get(setting))
        test_string = user_password
        for c in chars:
            test_string = test_string.replace(c, '')
        return (setting_as_int, len(user_password) - len(test_string))

    def matches_policy(item, policy_fails):
        return "*" if item in policy_fails else ""

    policy = []
    policy_fails = {}

    # If either policy is enabled check basics first ... this is obvious!
    if Setting().get('pwd_enforce_characters') or Setting().get('pwd_enforce_complexity'):
        # Cannot contain username
        if user.username in password:
            policy_fails["username"] = True
        policy.append(f"{matches_policy('username', policy_fails)}cannot contain username")

        # Cannot contain password
        if user.firstname in password:
            policy_fails["firstname"] = True
        policy.append(f"{matches_policy('firstname', policy_fails)}cannot contain firstname")

        # Cannot contain lastname
        if user.lastname in password:
            policy_fails["lastname"] = True
        policy.append(f"{matches_policy('lastname', policy_fails)}cannot contain lastname")

        # Cannot contain email
        if user.email in password:
            policy_fails["email"] = True
        policy.append(f"{matches_policy('email', policy_fails)}cannot contain email")

    # Check if we're enforcing character requirements
    if Setting().get('pwd_enforce_characters'):
        # Length
        pwd_min_len_setting = int(Setting().get('pwd_min_len'))
        pwd_len = len(password)
        if pwd_len < pwd_min_len_setting:
            policy_fails["length"] = True
        policy.append(f"{matches_policy('length', policy_fails)}length={pwd_len}/{pwd_min_len_setting}")
        # Digits
        (pwd_min_digits_setting, pwd_digits) = check_policy(string.digits, password, 'pwd_min_digits')
        if pwd_digits < pwd_min_digits_setting:
            policy_fails["digits"] = True
        policy.append(f"{matches_policy('digits', policy_fails)}digits={pwd_digits}/{pwd_min_digits_setting}")
        # Lowercase
        (pwd_min_lowercase_setting, pwd_lowercase) = check_policy(string.digits, password, 'pwd_min_lowercase')
        if pwd_lowercase < pwd_min_lowercase_setting:
            policy_fails["lowercase"] = True
        policy.append(
            f"{matches_policy('lowercase', policy_fails)}lowercase={pwd_lowercase}/{pwd_min_lowercase_setting}")
        # Uppercase
        (pwd_min_uppercase_setting, pwd_uppercase) = check_policy(string.digits, password, 'pwd_min_uppercase')
        if pwd_uppercase < pwd_min_uppercase_setting:
            policy_fails["uppercase"] = True
        policy.append(
            f"{matches_policy('uppercase', policy_fails)}uppercase={pwd_uppercase}/{pwd_min_uppercase_setting}")
        # Special
        (pwd_min_special_setting, pwd_special) = check_policy(string.digits, password, 'pwd_min_special')
        if pwd_special < pwd_min_special_setting:
            policy_fails["special"] = True
        policy.append(f"{matches_policy('special', policy_fails)}special={pwd_special}/{pwd_min_special_setting}")

    if Setting().get('pwd_enforce_complexity'):
        # Complexity checking
        zxcvbn_inputs = []
        for input in (user.firstname, user.lastname, user.username, user.email):
            if len(input):
                zxcvbn_inputs.append(input)

        result = zxcvbn(password, user_inputs=zxcvbn_inputs)
        pwd_min_complexity_setting = int(Setting().get('pwd_min_complexity'))
        pwd_complexity = result['guesses_log10']
        if pwd_complexity < pwd_min_complexity_setting:
            policy_fails["complexity"] = True
        policy.append(
            f"{matches_policy('complexity', policy_fails)}complexity={pwd_complexity:.0f}/{pwd_min_complexity_setting}")

    policy_str = {"password": f"Fails policy: {', '.join(policy)}. Items prefixed with '*' failed."}

    # NK: the first item in the tuple indicates a PASS, so, we check for any True's and negate that
    return (not any(policy_fails.values()), policy_str)


@index_bp.route('/register', methods=['GET', 'POST'])
def register():
    CAPTCHA_ENABLE = current_app.config.get('CAPTCHA_ENABLE')
    if Setting().get('signup_enabled'):
        if current_user.is_authenticated:
            return redirect(url_for('index.index'))
        if request.method == 'GET':
            return render_template('register.html.jinja', captcha_enable=CAPTCHA_ENABLE)
        elif request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            firstname = request.form.get('firstname', '').strip()
            lastname = request.form.get('lastname', '').strip()
            # email = request.form.get('email', '').strip()
            rpassword = request.form.get('rpassword', '')

            # is_valid_email = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

            error_messages = {}
            if not firstname:
                error_messages['firstname'] = 'First Name is required'
            if not lastname:
                error_messages['lastname'] = 'Last Name is required'
            if not username:
                error_messages['username'] = 'Username is required'
            if not password:
                error_messages['password'] = 'Password is required'
            if not rpassword:
                error_messages['rpassword'] = 'Password confirmation is required'
            # if not email:
            #     error_messages['email'] = 'Email is required'
            # if not is_valid_email.match(email):
            #     error_messages['email'] = 'Invalid email address'
            if password != rpassword:
                error_messages['password'] = 'Password confirmation does not match'
                error_messages['rpassword'] = 'Password confirmation does not match'

            if not captcha.validate():
                return render_template(
                    'register.html.jinja', error='Invalid CAPTCHA answer', error_messages=error_messages,
                    captcha_enable=CAPTCHA_ENABLE)

            if error_messages:
                return render_template('register.html.jinja', error_messages=error_messages, captcha_enable=CAPTCHA_ENABLE)

            user = User(username=username,
                        plain_text_password=password,
                        firstname=firstname,
                        lastname=lastname,
                        # email=email
                        )

            (password_policy_pass, password_policy) = password_policy_check(user, password)
            if not password_policy_pass:
                return render_template('register.html.jinja', error_messages=password_policy, captcha_enable=CAPTCHA_ENABLE)

            try:
                result = user.create_local_user()
                if result and result['status']:
                    # if Setting().get('verify_user_email'):
                    #     send_account_verification(email)
                #     if Setting().get('otp_force') and Setting().get('otp_field_enabled'):
                #         user.update_profile(enable_otp=True)
                #         prepare_welcome_user(user.id)
                #         return redirect(url_for('index.welcome'))
                #     else:
                #         return redirect(url_for('index.login'))
                # else:
                #     return render_template('register.html.jinja',
                #                            error=result['msg'], captcha_enable=CAPTCHA_ENABLE)
                    return redirect(url_for('index.index'))
            except Exception as e:
                return render_template('register.html.jinja', error=e, captcha_enable=CAPTCHA_ENABLE)
        else:
            return render_template('errors/404.html.jinja'), 404
    else:
        return render_template('errors/403.html.jinja'), 403


### START SUDIS AUTHENTICATION ###
@index_bp.route('/sudis/login')
def sudis_login():
    if not Setting().get('sudis_enabled'):
        current_app.logger.error("SUDIS authentication is disabled.")
        abort(400)
    if g.user is not None and current_user.is_authenticated:
        return redirect(url_for('dashboard.dashboard'))
    
    # from onelogin.saml2.utils import OneLogin_Saml2_Utils
    # req = sudis.prepare_flask_request(request)
    # if not req:
    #     abort(500)
    # auth = sudis.init_saml_auth(req)
    # redirect_url = OneLogin_Saml2_Utils.get_self_url(req) + url_for(
    #     'index.saml_authorized')
    # return redirect(auth.login(return_to=redirect_url))
    # return redirect(req)
    data = sudis.get_form_data()
    current_app.logger.debug(data)
    post_form = sudis.build_post_form(
        "http://idp.int.sudis.at-consulting.ru",
        data.get("SAMLRequest"),
        data.get("RelayState")
        )
    current_app.logger.debug(post_form)
    return post_form
    


# @index_bp.route('/sudis/metadata')
# def saml_metadata():
#     if not Setting().get('sudis_enabled', False):
#         current_app.logger.error("SAML authentication is disabled.")
#         abort(400)
#     from onelogin.saml2.utils import OneLogin_Saml2_Utils
#     req = sudis.prepare_flask_request(request)
#     auth = sudis.init_saml_auth(req)
#     settings = auth.get_settings()
#     metadata = settings.get_sp_metadata()
#     errors = settings.validate_metadata(metadata)

#     if len(errors) == 0:
#         resp = make_response(metadata, 200)
#         resp.headers['Content-Type'] = 'text/xml'
#     else:
#         resp = make_response(errors.join(', '), 500)
#     return resp


@index_bp.route('/sudis/authorized', methods=['GET', 'POST'])
@csrf.exempt
def saml_authorized():
    errors = []
    if not Setting().get('sudis_enabled'):
        current_app.logger.error("SUDIS authentication is disabled.")
        abort(400)
    return jsonify({"request": request.content_encoding})

def create_group_to_account_mapping():
    group_to_account_mapping_string = current_app.config.get(
        'SAML_GROUP_TO_ACCOUNT_MAPPING', None)
    if group_to_account_mapping_string and len(
            group_to_account_mapping_string.strip()) > 0:
        group_to_account_mapping = group_to_account_mapping_string.split(',')
    else:
        group_to_account_mapping = []
    return group_to_account_mapping


def handle_account(account_name, account_description=""):
    clean_name = Account.sanitize_name(account_name)
    account = Account.query.filter_by(name=clean_name).first()
    if not account:
        account = Account(name=clean_name,
                          description=account_description,
                          contact='',
                          mail='')
        account.create_account()
        history = History(msg='Account {0} created'.format(account.name),
                          created_by='OIDC/SAML Assertion')
        history.add()
    else:
        account.description = account_description
        account.update_account()
    return account


def uplift_to_admin(user):
    if user.role.name != 'Administrator':
        user.role_id = Role.query.filter_by(name='Administrator').first().id
        history = History(msg='Promoting {0} to administrator'.format(
            user.username),
            created_by='SAML Assertion')
        history.add()


def uplift_to_operator(user):
    if user.role.name != 'Operator':
        user.role_id = Role.query.filter_by(name='Operator').first().id
        history = History(msg='Promoting {0} to operator'.format(
            user.username),
            created_by='SAML Assertion')
        history.add()


@index_bp.route('/sudis/sls')
def sudis_logout():
    req = sudis.prepare_flask_request(request)
    auth = sudis.init_saml_auth(req)
    url = auth.process_slo()
    errors = auth.get_errors()
    if len(errors) == 0:
        clear_session()
        if url is not None:
            return redirect(url)
        elif current_app.config.get('SAML_LOGOUT_URL') is not None:
            return redirect(current_app.config.get('SAML_LOGOUT_URL'))
        else:
            return redirect(url_for('login'))
    else:
        return render_template('errors/sudis.html.jinja', errors=errors)


### END SAML AUTHENTICATION ###


@index_bp.route('/swagger', methods=['GET'])
def swagger_spec():
    if not Setting().get('enable_api'):
        return jsonify({"enable_api": False})
    try:
        spec_path = os.path.join(current_app.root_path, "swagger-spec.yaml")
        spec = open(spec_path, 'r')
        loaded_spec = load(spec.read(), Loader)
    except Exception as e:
        current_app.logger.error(
            'Cannot view swagger spec. Error: {0}'.format(e))
        current_app.logger.debug(traceback.format_exc())
        abort(500)

    resp = make_response(json.dumps(loaded_spec), 200)
    resp.headers['Content-Type'] = 'application/json'

    return resp
