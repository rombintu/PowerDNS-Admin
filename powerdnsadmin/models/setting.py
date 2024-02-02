import sys
import traceback

import pytimeparse
from ast import literal_eval
# from distutils.util import strtobool
from flask import current_app

from .base import db


class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, index=True)
    value = db.Column(db.Text())
    
    types = {
        'maintenance': bool,
        # 'fullscreen_layout': bool,
        'record_helper': bool,
        # 'login_ldap_first': bool,
        # 'default_record_table_size': int,
        # 'default_domain_table_size': int,
        'auto_ptr': bool,
        # 'record_quick_edit': bool,
        # 'pretty_ipv6_ptr': bool,
        # 'dnssec_admins_only': bool,
        # 'allow_user_create_domain': bool,
        # 'allow_user_remove_domain': bool,
        'allow_user_view_history': bool,
        # 'custom_history_header': str,
        # 'delete_sso_accounts': bool,
        'bg_domain_updates': bool,
        # 'enable_api_rr_history': bool,
        # 'preserve_history': bool,
        'site_name': str,
        'site_url': str,
        'session_timeout': int,
        'warn_session_timeout': bool,
        'pdns_api_url': str,
        'pdns_api_key': str,
        'pdns_api_timeout': int,
        'pdns_version': str,
        'verify_ssl_connections': bool,
        # 'verify_user_email': bool,
        'enforce_api_ttl': bool,
        'ttl_options': str,
        # 'otp_field_enabled': bool,
        # 'custom_css': str,
        # 'otp_force': bool,
        'max_history_records': int,
        # 'deny_domain_override': bool,
        # 'account_name_extra_chars': bool,
        # 'gravatar_enabled': bool,
        'forward_records_allow_edit': dict,
        'reverse_records_allow_edit': dict,
        'local_db_enabled': bool,
        'signup_enabled': bool,
        'pwd_enforce_characters': bool,
        'pwd_min_len': int,
        'pwd_min_lowercase': int,
        'pwd_min_uppercase': int,
        'pwd_min_digits': int,
        'pwd_min_special': int,
        'pwd_enforce_complexity': bool,
        'pwd_min_complexity': int,
        'sudis_enabled': bool,
        'cms_url': str,
        'sender_key_name': str,
        'recipient_key_name': str,
        'sp_name': str,
        'sp_consume_url': str,
        'sudis_sso_url': str,
        'sudis_sls_url': str,
        'sudis_sso_binding': str,
        'sudis_sls_binding': str,
        
        'enable_api': bool
    }
    
    defaults = {
        # General Settings
        'maintenance': False,
        # 'fullscreen_layout': True,
        'record_helper': True,
        # 'login_ldap_first': True,
        # 'default_record_table_size': 15,
        # 'default_domain_table_size': 10,
        'auto_ptr': False,
        # 'record_quick_edit': True,
        # 'pretty_ipv6_ptr': False,
        # 'dnssec_admins_only': False,
        # 'allow_user_create_domain': False,
        # 'allow_user_remove_domain': False,
        'allow_user_view_history': True,
        # 'custom_history_header': '',
        # 'delete_sso_accounts': False,
        'bg_domain_updates': False,
        # 'enable_api_rr_history': True,
        # 'preserve_history': False,
        'site_name': 'PowerDNS-Admin',
        'site_url': 'http://localhost:9191',
        'session_timeout': 10,
        'warn_session_timeout': True,
        'pdns_api_url': '',
        'pdns_api_key': '',
        'pdns_api_timeout': 30,
        'pdns_version': '4.1.1',
        'verify_ssl_connections': True,
        # 'verify_user_email': False,
        'enforce_api_ttl': False,
        'enable_api': False,
        'ttl_options': '1 minute,5 minutes,30 minutes,60 minutes,24 hours',
        # 'otp_field_enabled': True,
        # 'custom_css': '',
        # 'otp_force': False,
        'max_history_records': 1000,
        # 'deny_domain_override': False,
        # 'account_name_extra_chars': False,
        # 'gravatar_enabled': False,

        # Local Authentication Settings
        'local_db_enabled': True,
        'signup_enabled': True,
        'pwd_enforce_characters': False,
        'pwd_min_len': 10,
        'pwd_min_lowercase': 3,
        'pwd_min_uppercase': 2,
        'pwd_min_digits': 2,
        'pwd_min_special': 1,
        'pwd_enforce_complexity': False,
        'pwd_min_complexity': 11,

        'sudis_enabled': False,
        'cms_url': 'http://127.0.0.1:8001',
        'sender_key_name': 'PowerDNS-Admin',
        'recipient_key_name': 'idp',
        'sp_name': 'pda',
        'sp_consume_url': 'http://localhost:9191/sudis/authorized',
        'sudis_sso_url': 'http://idp.int.sudis.at-consulting.ru/idp/profile/SAML2/POSTGOST/SSO',
        'sudis_sls_url': 'http://idp.int.sudis.at-consulting.ru/idp/Logout?logoutRedirectUrl=http%3A%2F%2Fr4t.ru',
        'sudis_sso_binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-RFC4490',
        'sudis_sls_binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        

        # Zone Record Settings
        'forward_records_allow_edit': {
            'A': True,
            'AAAA': True,
            'AFSDB': False,
            'ALIAS': False,
            'CAA': True,
            'CERT': False,
            'CDNSKEY': False,
            'CDS': False,
            'CNAME': True,
            'DNSKEY': False,
            'DNAME': False,
            'DS': False,
            'HINFO': False,
            'KEY': False,
            'LOC': True,
            'LUA': False,
            'MX': True,
            'NAPTR': False,
            'NS': True,
            'NSEC': False,
            'NSEC3': False,
            'NSEC3PARAM': False,
            'OPENPGPKEY': False,
            'PTR': True,
            'RP': False,
            'RRSIG': False,
            'SOA': False,
            'SPF': True,
            'SSHFP': False,
            'SRV': True,
            'TKEY': False,
            'TSIG': False,
            'TLSA': False,
            'SMIMEA': False,
            'TXT': True,
            'URI': False
        },
        'reverse_records_allow_edit': {
            'A': False,
            'AAAA': False,
            'AFSDB': False,
            'ALIAS': False,
            'CAA': False,
            'CERT': False,
            'CDNSKEY': False,
            'CDS': False,
            'CNAME': False,
            'DNSKEY': False,
            'DNAME': False,
            'DS': False,
            'HINFO': False,
            'KEY': False,
            'LOC': True,
            'LUA': False,
            'MX': False,
            'NAPTR': False,
            'NS': True,
            'NSEC': False,
            'NSEC3': False,
            'NSEC3PARAM': False,
            'OPENPGPKEY': False,
            'PTR': True,
            'RP': False,
            'RRSIG': False,
            'SOA': False,
            'SPF': False,
            'SSHFP': False,
            'SRV': False,
            'TKEY': False,
            'TSIG': False,
            'TLSA': False,
            'SMIMEA': False,
            'TXT': True,
            'URI': False
        },
    }

    groups = {
        'authentication': [
            # Local Authentication Settings
            'local_db_enabled',
            'signup_enabled',
            'pwd_enforce_characters',
            'pwd_min_len',
            'pwd_min_lowercase',
            'pwd_min_uppercase',
            'pwd_min_digits',
            'pwd_min_special',
            'pwd_enforce_complexity',
            'pwd_min_complexity',

            # Sudis Authentication Settings
            'sudis_enabled',
            'cms_url',
            'sp_name',
            'sp_consume_url',
            'sudis_sso_url',
            'sudis_sls_url',
            'sudis_sso_binding',
            'sudis_sls_binding',
            'sender_key_name',
            'recipient_key_name'
            
        ]
    }

    def __init__(self, id=None, name=None, value=None):
        self.id = id
        self.name = name
        self.value = value

    # allow database autoincrement to do its own ID assignments
    def __init__(self, name=None, value=None):
        self.id = None
        self.name = name
        self.value = value

    def convert_type(self, name, value):
        import json
        from json import JSONDecodeError
        if name in self.types:
            var_type = self.types[name]

            # Handle boolean values
            if var_type == bool:
                if value == 'True' or value == 'true' or value == '1' or value is True:
                    return True
                else:
                    return False

            # Handle float values
            if var_type == float:
                return float(value)

            # Handle integer values
            if var_type == int:
                return int(value)

            if (var_type == dict or var_type == list) and isinstance(value, str) and len(value) > 0:
                try:
                    return json.loads(value)
                except JSONDecodeError as e:
                    pass

            if var_type == str:
                return str(value)

        return value

    def set_maintenance(self, mode):
        maintenance = Setting.query.filter(
            Setting.name == 'maintenance').first()

        if maintenance is None:
            value = self.defaults['maintenance']
            maintenance = Setting(name='maintenance', value=str(value))
            db.session.add(maintenance)

        mode = str(mode)

        try:
            if maintenance.value != mode:
                maintenance.value = mode
                db.session.commit()
            return True
        except Exception as e:
            current_app.logger.error('Cannot set maintenance to {0}. DETAIL: {1}'.format(
                mode, e))
            current_app.logger.debug(traceback.format_exec())
            db.session.rollback()
            return False

    def toggle(self, setting):
        current_setting = Setting.query.filter(Setting.name == setting).first()

        if current_setting is None:
            value = self.defaults[setting]
            current_setting = Setting(name=setting, value=str(value))
            db.session.add(current_setting)

        try:
            if current_setting.value == "True":
                current_setting.value = "False"
            else:
                current_setting.value = "True"
            db.session.commit()
            return True
        except Exception as e:
            current_app.logger.error('Cannot toggle setting {0}. DETAIL: {1}'.format(
                setting, e))
            current_app.logger.debug(traceback.format_exec())
            db.session.rollback()
            return False

    def set(self, setting, value):
        current_setting = Setting.query.filter(Setting.name == setting).first()

        if current_setting is None:
            current_setting = Setting(name=setting, value=None)
            db.session.add(current_setting)

        value = str(self.convert_type(setting, value))

        try:
            current_setting.value = value
            db.session.commit()
            return True
        except Exception as e:
            current_app.logger.error('Cannot edit setting {0}. DETAIL: {1}'.format(
                setting, e))
            current_app.logger.debug(traceback.format_exec())
            db.session.rollback()
            return False

    def get(self, setting):
        if setting in self.defaults:

            if setting.upper() in current_app.config:
                result = current_app.config[setting.upper()]
            else:
                result = self.query.filter(Setting.name == setting).first()

            if result is not None:
                if hasattr(result, 'value'):
                    result = result.value

                return self.convert_type(setting, result)
            else:
                return self.defaults[setting]
        else:
            current_app.logger.error('Unknown setting queried: {0}'.format(setting))

    def get_group(self, group):
        if not isinstance(group, list):
            group = self.groups[group]

        result = {}
        records = self.query.all()

        for record in records:
            if record.name in group:
                result[record.name] = self.convert_type(record.name, record.value)

        return result

    def get_records_allow_to_edit(self):
        return list(
            set(self.get_forward_records_allow_to_edit() +
                self.get_reverse_records_allow_to_edit()))

    def get_forward_records_allow_to_edit(self):
        records = self.get('forward_records_allow_edit')
        f_records = literal_eval(records) if isinstance(records,
                                                        str) else records
        r_name = [r for r in f_records if f_records[r]]
        # Sort alphabetically if python version is smaller than 3.6
        if sys.version_info[0] < 3 or (sys.version_info[0] == 3
                                       and sys.version_info[1] < 6):
            r_name.sort()
        return r_name

    def get_reverse_records_allow_to_edit(self):
        records = self.get('reverse_records_allow_edit')
        r_records = literal_eval(records) if isinstance(records,
                                                        str) else records
        r_name = [r for r in r_records if r_records[r]]
        # Sort alphabetically if python version is smaller than 3.6
        if sys.version_info[0] < 3 or (sys.version_info[0] == 3
                                       and sys.version_info[1] < 6):
            r_name.sort()
        return r_name

    def get_ttl_options(self):
        return [(pytimeparse.parse(ttl), ttl)
                for ttl in self.get('ttl_options').split(',')]
