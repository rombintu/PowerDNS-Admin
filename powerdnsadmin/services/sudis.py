# from datetime import datetime, timedelta
# from threading import Thread
from flask import current_app, Request
from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.settings import OneLogin_Saml2_Settings

# import json
import base64, re
import requests
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
from datetime import datetime
# from ..lib.certutil import KEY_FILE, CERT_FILE, create_self_signed_cert
from ..lib.utils import urlparse
from ..models.setting import Setting
# from onelogin.saml2.compat import to_bytes

def get_sudis_settings_data():
    return {
        "strict": True,
        "debug": True,
        "sp": {
            "entityId": "http://localhost.nickolsky.ddns.phoenixit.ru:9191",
            "assertionConsumerService": {
                "url": Setting().get('sp_consume_url'),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "singleLogoutService": {
                "url": "http://localhost.nickolsky.ddns.phoenixit.ru:9191/sudis/sls",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            # "attributeConsumingService": {
            #         "index": '1',
            #         "serviceName": Setting().get('sp_name'),
            #         "serviceDescription": "PowerDNS-Admin website",
                    # "requestedAttributes": [
                    #     {
                    #         "name": "",
                    #         "isRequired": False,
                    #         "nameFormat": "",
                    #         "friendlyName": "",
                    #         "attributeValue": []
                    #     }
                    # ]
            # },
            
        },

        "idp": {
            "entityId": "http://idp01.int.sudis.at-consulting.ru",
            "singleSignOnService": {
                "url": Setting().get('sudis_sso_url'),
                "binding": Setting().get('sudis_sso_binding')
            },
            "singleLogoutService": {
                "url": "http://idp01.int.sudis.at-consulting.ru/idp/Logout",
                "responseUrl": "http://localhost.nickolsky.ddns.phoenixit.ru:9191",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            }
        }
    }

def get_current_time():
    return datetime.now().strftime('%Y-%m-%dT%H:%M:%S%z')

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
    
class OneLogin_Saml2_Auth_Sudis(OneLogin_Saml2_Auth):
    # def _build_signature(self, data, saml_type, sign=None):
    #     assert saml_type in ('SAMLRequest', 'SAMLResponse')
    #     data['Signature'] = OneLogin_Saml2_Utils.b64encode(sign)
    # def add_request_signature(self, request_data, sign=None):
    #     return self._build_signature(request_data, 'SAMLRequest', sign)
    cms = CMS()
    def login(self, return_to=None, force_authn=False, is_passive=False, set_nameid_policy=True, name_id_value_req=None):
        """
        Initiates the SSO process.

        :param return_to: Optional argument. The target URL the user should be redirected to after login.
        :type return_to: string

        :param force_authn: Optional argument. When true the AuthNRequest will set the ForceAuthn='true'.
        :type force_authn: bool

        :param is_passive: Optional argument. When true the AuthNRequest will set the Ispassive='true'.
        :type is_passive: bool

        :param set_nameid_policy: Optional argument. When true the AuthNRequest will set a nameIdPolicy element.
        :type set_nameid_policy: bool

        :param name_id_value_req: Optional argument. Indicates to the IdP the subject that should be authenticated
        :type name_id_value_req: string

        :returns: Redirection URL
        :rtype: string
        """
        authn_request = self.authn_request_class(self._settings, force_authn, is_passive, set_nameid_policy, name_id_value_req)
        # self._last_request = authn_request.get_xml()
        # self._last_request_id = authn_request.get_id()

        # saml_request = authn_request.get_request()
        saml_request_sign = self.cms.message(authn_request.get_xml(), action="encode")
        saml_request = OneLogin_Saml2_Utils.deflate_and_base64_encode(
            saml_request_sign
        )
        
        form_data = {'SAMLRequest': saml_request}

        if return_to is not None:
            form_data['RelayState'] = return_to
        else:
            form_data['RelayState'] = OneLogin_Saml2_Utils.get_self_url_no_query(self._request_data)

        security = self._settings.get_security_data()
        if security.get('authnRequestsSigned', False):
            self.add_request_signature(form_data, security['signatureAlgorithm'])
        return self.get_sso_url(), form_data

class SUDIS(object):
    def __init__(self):
        if Setting().get("sudis_enabled"):
            self.cms = CMS()
        self.settings = OneLogin_Saml2_Settings(get_sudis_settings_data())
        self.saml_request = OneLogin_Saml2_Authn_Request(self.settings)
        # self.authn_request.    
        
    def xml_request_build(
            self,
            force_authn=False,
            is_passive=False,
            version="2.0"):
        root = ET.Element("saml2p:AuthnRequest", 
        {
            "xmlns:saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
            "AssertionConsumerServiceURL": Setting().get('sp_consume_url'),
            "Destination": Setting().get('sudis_sso_url'),
            "ForceAuthn": str(force_authn).lower(),
            "ID": f"{uuid.uuid4()}",
            "IsPassive": str(is_passive).lower(),
            "IssueInstant": f"{get_current_time()}",
            "ProtocolBinding": Setting().get('sudis_sso_binding'),
            "Version": version,
        })
    
        issuer = ET.SubElement(
            root, "saml2:Issuer", 
            {"xmlns:saml2": "urn:oasis:names:tc:SAML:2.0:assertion"})
        issuer.text = Setting().get('sp_name')
    
        # Создание XML из данных
        xml_data = ET.tostring(root, encoding="unicode")
        return xml_data
    
    def build_post_form(self, sso_url, saml_request, relay_state):
        return f"""<form method='post' action='{sso_url}'>
        <input type='hidden' name='SAMLRequest' value='{saml_request}'></input>
        <input type='hidden' name='RelayState' value='{relay_state}'></input>
    </form>
<script>window.onload = function () {'{'}document.forms[0].submit();{'}'}</script>"""
    
    # def get_saml_request(self):
    #     saml_request = self.xml_request_build()
    #     current_app.logger.debug(saml_request)
    #     saml_request_encoded = None
    #     try:
    #         saml_request_encoded = self.cms.message(saml_request, action="encode")
    #     except Exception as err:
    #         current_app.logger.error(err)
    #         return None
    #     if not saml_request_encoded:
    #         return None
    #     form_data = {
    #         "SAMLRequest": base64.b64encode(saml_request_encoded).decode(),
    #         "RelayState": Setting().get('sp_consume_url'),
    #     }
    #     # params = {'AuthType': "PASSWORD"}
    #     current_app.logger.debug(form_data)
    #     # response = None
    #     # try:
    #     #     response = requests.post(self.settings.get_idp_sso_url(), data=form_data)
    #     # except ConnectionError as err:
    #     #     current_app.logger.error(err)
    #     # # current_app.logger.debug(response.text)
    #     return form_data

    def get_form_data(self):
        # saml_request = self.saml_request.get_xml()
        saml_request = self.xml_request_build()
        current_app.logger.debug(saml_request)
        saml_request_encoded = None
        try:
            saml_request_encoded = self.cms.message(saml_request, action="encode")
        except Exception as err:
            current_app.logger.error(err)
            return None
        if not saml_request_encoded:
            return None
        form_data = {
            "SAMLRequest": base64.b64encode(saml_request_encoded).decode(),
            "RelayState": Setting().get('sp_consume_url'),
        }
        current_app.logger.debug(form_data)
        # response = None
        # try:
        #     response = requests.post("http://idp01.int.sudis.at-consulting.ru", data=form_data)
        # except ConnectionError as err:
        #     current_app.logger.error(err)
        # # current_app.logger.debug(response.text)
        return form_data

    def prepare_flask_request(self, request):
        # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
        url_data = urlparse(request.url)
        proto = request.headers.get('HTTP_X_FORWARDED_PROTO', request.scheme)
        return {
            'https': 'on' if proto == 'https' else 'off',
            'http_host': request.host,
            'server_port': url_data.port,
            'script_name': request.path,
            'get_data': request.args.copy(),
            'post_data': request.form.copy(),
            # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
            # 'lowercase_urlencoding': True,
            # 'query_string': request.query_string
        }

    def init_saml_auth(self, req):
        auth = OneLogin_Saml2_Auth_Sudis(req, self.settings)
        # auth.add_request_signature(req, self.get_form_data)
        return auth