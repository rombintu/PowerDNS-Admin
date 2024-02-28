# from datetime import datetime, timedelta
# from threading import Thread
from flask import current_app, Request, url_for
from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from ..services.overload import OneLogin_Saml2_Response_Sudis

# import json
import re
import requests
# import uuid
# import xml.etree.ElementTree as ET
from urllib.parse import urljoin
# from datetime import datetime
# from ..lib.certutil import KEY_FILE, CERT_FILE, create_self_signed_cert
from ..lib.utils import urlparse
from ..models.setting import Setting
# from onelogin.saml2.compat import to_bytes

def get_sudis_settings_data():
    return {
        "strict": False,
        "debug": True,
        "sp": {
            "entityId": Setting().get('sp_name'),
            "assertionConsumerService": {
                "url": Setting().get('sp_consume_url'),
                "binding": Setting().get('sudis_sso_binding'),
            },
            "attributeConsumingService": {
                    # "index": '1',
                    "serviceName": Setting().get('sp_name'),
                    "serviceDescription": "",
                    "requestedAttributes": [
                        {
                            "name": "email",
                            "isRequired": True,
                            "nameFormat": "",
                            "friendlyName": "",
                            "attributeValue": []
                        }
                    ]
            },
            
        },

        "idp": {
            "entityId": Setting().get('sudis_idp_url'),
            "singleSignOnService": {
                "url": Setting().get('sudis_sso_url'),
                "binding": Setting().get('sudis_sso_binding')
            },
            "singleLogoutService": {
                "url": Setting().get('sudis_sls_url'),
                "binding":  Setting().get('sudis_sls_binding'),
            }
        }
    }

def get_correct_url(request: Request):
    context_path = request.path
    request_uri = request.url
    context_beg = request_uri.find(context_path)
    context_end = context_beg + len(context_path)
    slash = "/"
    url = (context_beg < 0 or context_end == (len(request_uri) - 1)) \
        if request_uri else request_uri[context_end:]
    if not url.startswith(slash):
        url = slash + url
    return url

def is_filtered_request(request):
    correct_url = get_correct_url(request)
    pattern = r'^.*\.(jpg|JPG|gif|GIF|css|CSS|ico|ICO|js|JS)$'
    if re.match(pattern, urlparse(correct_url).path):
        return False
    else:
        return True
    
class CMS:
    def get_headers(self):
        return {
            'Content-Type': 'application/octet-stream',
            'X-senderkey': Setting().get('sender_key_name'),
            'X-recipientkey': Setting().get('recipient_key_name')
        }
    
    def message(self, body, action="encode", headers={}):
        if action not in ["encode", "decode"]:
            current_app.logger.debug("Set action: encode or decode")
            return None
        headers = dict(self.get_headers(), **headers)
        resp = requests.post(urljoin(Setting().get('cms_url'), action), body, headers=headers)
        if resp.ok:
            current_app.logger.debug("CryptoPro Response success")
        else:
            current_app.logger.error(f"CryptoPro Response error")
            return None
        return resp.content
    

class SUDIS(object):
    def __init__(self):
        if Setting().get("sudis_enabled"):
            self.cms = CMS()
        self.settings = OneLogin_Saml2_Settings(get_sudis_settings_data())

    def get_saml_crypto_encoded(self):
        authn_request = OneLogin_Saml2_Authn_Request(self.settings)
        current_app.logger.debug(f"GET XML >> {authn_request.get_xml()}")
        saml_request_crypto = self.cms.message(authn_request.get_xml(), action="encode")
        saml_request_crypto_encoded = OneLogin_Saml2_Utils.b64encode(saml_request_crypto)
        return saml_request_crypto_encoded
    
    def get_saml_from_crypto_encoded(self, req: dict):
        saml_response_crypto_encoded = req.get("post_data").get('SAMLResponse')
        if not saml_response_crypto_encoded:
            return None
        saml_response_crypto = OneLogin_Saml2_Utils.b64decode(saml_response_crypto_encoded)
        saml_response = self.cms.message(saml_response_crypto, action="decode")
        current_app.logger.debug(saml_response)
        saml_response_encoded = OneLogin_Saml2_Utils.b64encode(saml_response)
        return saml_response_encoded
    
    def prepare_flask_request(self, request: Request):
        # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
        url_data = urlparse(request.url)
        proto = request.headers.get('HTTP_X_FORWARDED_PROTO', request.scheme)
        return {
            'https': 'on' if proto == 'https' else 'off',
            'http_host': request.host,
            'server_port': url_data.port,
            'script_name': request.form.copy(),
            'get_data': request.args.copy(),
            'post_data': request.form.copy(),
            # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
            # 'lowercase_urlencoding': True,
            # 'query_string': request.query_string
        }

    def init_saml_auth(self, req):
        auth = OneLogin_Saml2_Auth(req, self.settings)
        auth.response_class = OneLogin_Saml2_Response_Sudis
        return auth