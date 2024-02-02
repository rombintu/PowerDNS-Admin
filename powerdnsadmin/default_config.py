import os
import urllib.parse
basedir = os.path.abspath(os.path.dirname(__file__))

### BASIC APP CONFIG
SALT = '$2b$12$yLUMTIfl21FKJQpTkRQXCu'
SECRET_KEY = 'e951e5a1f4b94151b360f47edf596dd2'
BIND_ADDRESS = '0.0.0.0'
PORT = 9191
HSTS_ENABLED = False
SERVER_EXTERNAL_SSL = True

SESSION_TYPE = 'sqlalchemy'
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_HTTPONLY = True

#CAPTCHA Config
CAPTCHA_ENABLE = True
CAPTCHA_LENGTH = 6
CAPTCHA_WIDTH = 160
CAPTCHA_HEIGHT = 60
CAPTCHA_SESSION_KEY = 'captcha_image'

### DATABASE CONFIG
SQLA_DB_USER = 'pda'
SQLA_DB_PASSWORD = 'changeme'
SQLA_DB_HOST = '127.0.0.1'
SQLA_DB_NAME = 'pda'
SQLALCHEMY_TRACK_MODIFICATIONS = True

### DATABASE - MySQL
# SQLALCHEMY_DATABASE_URI = 'mysql://{}:{}@{}/{}'.format(
#     urllib.parse.quote_plus(SQLA_DB_USER),
#     urllib.parse.quote_plus(SQLA_DB_PASSWORD),
#     SQLA_DB_HOST,
#     SQLA_DB_NAME
# )

### DATABASE - SQLite
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'pdns.db')

# # SAML Authnetication
# SAML_ENABLED = False
# SAML_DEBUG = True
# SAML_PATH = os.path.join(os.path.dirname(__file__), 'saml')
# # # ##Example for ADFS Metadata-URL
# SAML_METADATA_URL = 'http://openam.testing.ru:8080/openam/saml2/jsp/exportmetadata.jsp'
# # # #Cache Lifetime in Seconds
SAML_METADATA_CACHE_LIFETIME = 1

# SAML SSO binding format to use
# Default: library default (urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect)
SAML_IDP_SSO_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-RFC4490'

# EntityID of the IdP to use. Only needed if more than one IdP is
#   in the SAML_METADATA_URL
## Default: First (only) IdP in the SAML_METADATA_URL
## Example: https://idp.example.edu/idp
SAML_IDP_ENTITY_ID = 'http://idp01.int.sudis.at-consulting.ru/idp/'
# NameID format to request
## Default: The SAML NameID Format in the metadata if present,
##   otherwise urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
## Example: urn:oid:0.9.2342.19200300.100.1.1
# SAML_NAMEID_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified=mail'

# Following parameter defines RequestedAttributes section in SAML metadata
# since certain iDPs require explicit attribute request. If not provided section
# will not be available in metadata.
#
# Possible attributes:
# name (mandatory), nameFormat, isRequired, friendlyName
#
# NOTE: This parameter requires to be entered in valid JSON format as displayed below
# and multiple attributes can given
#
# Following example:

# SAML_SP_REQUESTED_ATTRIBUTES = '[ \
# {"name": "urn:oid:0.9.2342.19200300.100.1.3", "nameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "isRequired": true, "friendlyName": "email"}, \
# {"name": "mail", "isRequired": false, "friendlyName": "test-field"} \
# ]'

# produces following metadata section:
# <md:AttributeConsumingService index="1">
# <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="email" isRequired="true"/>
# <md:RequestedAttribute Name="mail" FriendlyName="test-field"/>
# </md:AttributeConsumingService>


# Attribute to use for Email address
## Default: email
## Example: urn:oid:0.9.2342.19200300.100.1.3
# SAML_ATTRIBUTE_EMAIL = 'urn:oid:0.9.2342.19200300.100.1.3'
# SAML_ATTRIBUTE_EMAIL = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress=mail'
# # Attribute to use for Given name
# ## Default: givenname
# ## Example: urn:oid:2.5.4.42
# SAML_ATTRIBUTE_GIVENNAME = 'urn:oid:2.5.4.42'

# # Attribute to use for Surname
# ## Default: surname
# ## Example: urn:oid:2.5.4.4
# SAML_ATTRIBUTE_SURNAME = 'urn:oid:2.5.4.4'

# # Attribute to use for username
# ## Default: Use NameID instead
# ## Example: urn:oid:0.9.2342.19200300.100.1.1
# SAML_ATTRIBUTE_USERNAME = 'urn:oid:0.9.2342.19200300.100.1.1'

# # Attribute to get admin status from
# ## Default: Don't control admin with SAML attribute
# ## Example: https://example.edu/pdns-admin
# ## If set, look for the value 'true' to set a user as an administrator
# ## If not included in assertion, or set to something other than 'true',
# ##  the user is set as a non-administrator user.
# SAML_ATTRIBUTE_ADMIN = 'https://example.edu/pdns-admin'

# # Attribute to get admin status for groups with the IdP
# ### Default: Don't set administrator group with SAML attributes
# SAML_GROUP_ADMIN_NAME = 'GroupName'

# # Attribute to get operator status for groups with the IdP
# ### Default: Don't set operator group with SAML attributes
# SAML_GROUP_OPERATOR_NAME = 'operators'

# ## Attribute to get account names from
# ### Default: Don't control accounts with SAML attribute
# ### If set, the user will be added and removed from accounts to match
# ###  what's in the login assertion. Accounts that don't exist will
# ###  be created and the user added to them.
# SAML_ATTRIBUTE_ACCOUNT = 'https://example.edu/pdns-account'

# ## Attribute name that aggregates group names
# ### Default: Don't collect IdP groups from SAML group attributes
# ### In Okta, you can assign administrators by group using "Group Attribute Statements."
# ### In this case, the SAML_ATTRIBUTE_GROUP will be the attribute name for a collection of
# ###  groups passed in the SAML assertion.  From there, you can specify a SAML_GROUP_ADMIN_NAME.
# ### If the user is a member of this group, and that group name is included in the collection,
# ###   the user will be set as an administrator.
# #SAML_ATTRIBUTE_GROUP = 'https://example.edu/pdns-groups'
# SAML_GROUP_ADMIN_NAME = 'operators'

# SAML_SP_ENTITY_ID = 'http://openam.ru:8080/openam'
# SAML_SP_CONTACT_NAME = 'admin'
# SAML_SP_CONTACT_MAIL = 'admin@admin.com'

# Configures the path to certificate file and it's respective private key file
# This pair is used for signing metadata, encrypting tokens and all other signing/encryption
# tasks during communication between iDP and SP
# NOTE: if this two parameters aren't explicitly provided, self-signed certificate-key pair
# will be generated in "PowerDNS-Admin" root directory
# ###########################################################################################
# CAUTION: For production use, usage of self-signed certificates it's highly discouraged.
# Use certificates from trusted CA instead
# ###########################################################################################
# SAML_CERT = '/etc/pki/powerdns-admin/cert.crt'
# SAML_KEY = '/etc/pki/powerdns-admin/key.pem'

# Configures if SAML tokens should be encrypted.
# SAML_SIGN_REQUEST = False # TODO CMS
# #Use SAML standard logout mechanism retreived from idp metadata
# #If configured false don't care about SAML session on logout.
# #Logout from PowerDNS-Admin only and keep SAML session authenticated.
SAML_LOGOUT = True
# #Configure to redirect to a different url then PowerDNS-Admin login after SAML logout
# #for example redirect to google.com after successful saml logout
SAML_LOGOUT_URL = 'http://idp01.int.sudis.at-consulting.ru/idp/Logout?logoutRedirectUrl=http%3A%2F%2Fpda.ru'

# SAML_ASSERTION_ENCRYPTED = True

# # Some IdPs, like Okta, do not return Attribute Statements by default
# # Set the following to False if you are using Okta and not manually configuring Attribute Statements
# # #SAML_WANT_ATTRIBUTE_STATEMENT = True

VERSION = "0.4.2-cloudate"