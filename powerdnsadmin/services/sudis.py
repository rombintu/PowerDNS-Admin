# from datetime import datetime, timedelta
# from threading import Thread
from flask import current_app, Request, url_for
# import json
import os, base64, re
import requests
import json
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
from datetime import datetime
# from ..lib.certutil import KEY_FILE, CERT_FILE, create_self_signed_cert
from ..lib.utils import urlparse
from ..models.setting import Setting
# from onelogin.saml2.compat import to_bytes

curdir = os.getcwd()

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
    
def get_current_time():
    return datetime.now().strftime('%Y-%m-%dT%H:%M:%S%z')

# TODO Загружает один раз и настройки не меняются
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
            # "http://localhost.nickolsky.ddns.phoenixit.ru:9191/sudis/authorized"
            # self.sudis_url_sls = Setting().get('sudis_sls_url')
            # self.sudis_binding_sso = 
            # self.sudis_binding_sls = Setting().get('sudis_sls_binding')

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
    
    def post_saml_request(self):
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
        # params = {'AuthType': "PASSWORD"}
        current_app.logger.debug(form_data)
        response = None
        try:
            response = requests.post("http://idp.int.sudis.at-consulting.ru", data=form_data)
        except ConnectionError as err:
            current_app.logger.error(err)
        # current_app.logger.debug(response.text)
        return response

    # def init_saml_auth(self, request: dict):
    #     # own_url = ''
    #     # if req['https'] == 'on':
    #     #     own_url = 'https://'
    #     # else:
    #     #     own_url = 'http://'
    #     # own_url += req['http_host']
    #     # metadata = self.get_idp_data()
    #     saml_settings = self.OneLogin_Saml2_Settings(custom_base_path=self.settings_path)
    #     authn_request = self.OneLogin_Saml2_Authn_Request(saml_settings)
    #     saml_request = authn_request.get_request()
    #     try:
    #         req_encoded_cms = self.cms.message(saml_request, action="encode")
    #     except Exception as err:
    #         current_app.logger.error(err)
    #         return None
    #     req_encoded_base64 = base64.b64encode(req_encoded_cms).decode()
    #     current_app.logger.debug(req_encoded_base64)
    #     # request["get_data"] = req_encoded_base64
    #     auth = self.OneLogin_Saml2_Auth(request, saml_settings)
        
    #     return auth
        