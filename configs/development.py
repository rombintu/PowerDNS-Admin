import os
#import urllib.parse
basedir = os.path.abspath(os.path.dirname(__file__))

### BASIC APP CONFIG
SALT = '$2b$12$yLUMTIfl21FKJQpTkRQXCu'
SECRET_KEY = 'e951e5a1f4b94151b360f47edf596dd2'
BIND_ADDRESS = '0.0.0.0'
PORT = 9191
SERVER_EXTERNAL_SSL = None

### DATABASE CONFIG
SQLA_DB_USER = 'pda'
SQLA_DB_PASSWORD = 'changeme'
SQLA_DB_HOST = '127.0.0.1'
SQLA_DB_NAME = 'pda'
SQLALCHEMY_TRACK_MODIFICATIONS = True

#CAPTCHA Config
CAPTCHA_ENABLE = True
CAPTCHA_LENGTH = 6
CAPTCHA_WIDTH = 160
CAPTCHA_HEIGHT = 60
CAPTCHA_SESSION_KEY = 'captcha_image'

#Server side sessions tracking
#Set to TRUE for CAPTCHA, or enable another stateful session tracking system
SESSION_TYPE = 'sqlalchemy'

### DATABASE - MySQL
## Don't forget to uncomment the import in the top
#SQLALCHEMY_DATABASE_URI = 'mysql://{}:{}@{}/{}'.format(
#    urllib.parse.quote_plus(SQLA_DB_USER),
#    urllib.parse.quote_plus(SQLA_DB_PASSWORD),
#    SQLA_DB_HOST,
#    SQLA_DB_NAME
#)

### DATABASE - PostgreSQL
## Don't forget to uncomment the import in the top
#SQLALCHEMY_DATABASE_URI = 'postgres://{}:{}@{}/{}'.format(
#    urllib.parse.quote_plus(SQLA_DB_USER),
#    urllib.parse.quote_plus(SQLA_DB_PASSWORD),
#    SQLA_DB_HOST,
#    SQLA_DB_NAME
#)

### DATABASE - SQLite
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'pdns.db')

### SMTP config
# MAIL_SERVER = 'localhost'
# MAIL_PORT = 25
# MAIL_DEBUG = False
# MAIL_USE_TLS = False
# MAIL_USE_SSL = False
# MAIL_USERNAME = None
# MAIL_PASSWORD = None
# MAIL_DEFAULT_SENDER = ('PowerDNS-Admin', 'noreply@domain.ltd')

VERSION = "0.4.1-cloudate"