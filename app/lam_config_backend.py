import re
import os
from lam_logger import log_info
from lam_exceptions import LamConfigBackendException
from lam_rex import g_rex_email

class LamConfigBackend():
  def __init__(self):
    self.milter_name = 'ldap-acl-milter'
    self.milter_mode = 'test'
    self.milter_socket = '/socket/{}'.format(self.milter_name)
    self.milter_timeout = 60
    self.milter_reject_message = 'Security policy violation!'
    self.milter_tmpfail_message = 'Service temporarily not available! Please try again later.'
    self.ldap_server = 'ldap://127.0.0.1:389'
    self.ldap_server_connect_timeout = 3
    self.ldap_binddn = 'cn=ldap-reader,ou=binds,dc=example,dc=org'
    self.ldap_bindpw = 'TopSecret;-)'
    self.ldap_base = 'ou=lam,ou=services,dc=example,dc=org'
    self.ldap_query = '(&(mail=%rcpt%)(allowedEnvelopeSender=%from%))'
    self.milter_schema = False
    self.milter_schema_wildcard_domain = False
    self.milter_expect_auth = False
    self.milter_whitelisted_rcpts = {}
    self.milter_dkim_enabled = False
    self.milter_trusted_authservid = None
    self.milter_max_rcpt_enabled = False
    self.milter_max_rcpt = 1
    self.milter_allow_null_sender = False

    if 'MILTER_NAME' in os.environ:
      self.milter_name = os.environ['MILTER_NAME']

    if 'MILTER_MODE' in os.environ:
      if re.match(r'^test|reject$',os.environ['MILTER_MODE'], re.IGNORECASE):
        self.milter_mode = os.environ['MILTER_MODE'].lower()
    log_info("ENV[MILTER_MODE]: {}". format(self.milter_mode))

    if 'MILTER_SOCKET' in os.environ:
      self.milter_socket = os.environ['MILTER_SOCKET']
    log_info("ENV[MILTER_SOCKET]: {}".format(self.milter_socket))

    if 'MILTER_TIMEOUT' in os.environ:
      if os.environ['MILTER_TIMEOUT'].isnumeric():
        self.milter_timeout = int(os.environ['MILTER_TIMEOUT'])
      else:
        raise LamConfigBackendException("ENV[MILTER_TIMEOUT] must be numeric!")
    log_info("ENV[MILTER_TIMEOUT]: {}".format(self.milter_timeout))

    if 'MILTER_SCHEMA' in os.environ:
      if re.match(r'^true$', os.environ['MILTER_SCHEMA'], re.IGNORECASE):
        self.milter_schema = True
        if 'MILTER_SCHEMA_WILDCARD_DOMAIN' in os.environ:
          if re.match(r'^true$', os.environ['MILTER_SCHEMA_WILDCARD_DOMAIN'], re.IGNORECASE):
            self.milter_schema_wildcard_domain = True
    log_info("ENV[MILTER_SCHEMA]: {}".format(self.milter_schema))
    log_info(
      "ENV[MILTER_SCHEMA_WILDCARD_DOMAIN]: {}".format(
        self.milter_schema_wildcard_domain
      )
    )

    if 'LDAP_SERVER' not in os.environ:
      raise LamConfigBackendException(
        "Missing ENV[LDAP_SERVER], e.g. {}".format(self.ldap_server)
      )
    self.ldap_server = os.environ['LDAP_SERVER']
    log_info("ENV[LDAP_SERVER]: {}".format(self.ldap_server))
    
    if 'LDAP_SERVER_CONNECT_TIMEOUT' in os.environ:
      if not os.environ['LDAP_SERVER_CONNECT_TIMEOUT'].isnumeric():
        raise LamConfigBackendException(
          "ENV[LDAP_SERVER_CONNECT_TIMEOUT] must be numeric!"
        )
      self.ldap_server_connect_timeout = int(os.environ['LDAP_SERVER_CONNECT_TIMEOUT'])
    log_info("ENV[LDAP_SERVER_CONNECT_TIMEOUT]: {}".format(
      self.ldap_server_connect_timeout
    ))
    
    if 'LDAP_BINDDN' in os.environ:
      self.ldap_binddn = os.environ['LDAP_BINDDN']
    if 'LDAP_BINDPW' in os.environ:
      self.ldap_bindpw = os.environ['LDAP_BINDPW']
    
    if 'LDAP_BASE' not in os.environ:
      raise LamConfigBackendException(
        "Missing ENV[LDAP_BASE], e.g. {}".format(self.ldap_base)
      )
    self.ldap_base = os.environ['LDAP_BASE']
    log_info("ENV[LDAP_BASE]: {}".format(self.ldap_base))
    
    if 'LDAP_QUERY' not in os.environ:
      if self.milter_schema == False:
        raise LamConfigBackendException(
          "ENV[MILTER_SCHEMA] is disabled and ENV[LDAP_QUERY] is not set instead!"
        )
    else:
      self.ldap_query = os.environ['LDAP_QUERY']
      log_info("ENV[LDAP_QUERY]: {}".format(self.ldap_query))
    
    if 'MILTER_REJECT_MESSAGE' in os.environ:
      self.milter_reject_message = os.environ['MILTER_REJECT_MESSAGE']
    log_info("ENV[MILTER_REJECT_MESSAGE]: {}".format(self.milter_reject_message))
    
    if 'MILTER_TMPFAIL_MESSAGE' in os.environ:
      self.milter_tmpfail_message = os.environ['MILTER_TMPFAIL_MESSAGE']
    log_info("ENV[MILTER_TMPFAIL_MESSAGE]: {}".format(self.milter_tmpfail_message))
    
    if 'MILTER_EXPECT_AUTH' in os.environ:
      if re.match(r'^true$', os.environ['MILTER_EXPECT_AUTH'], re.IGNORECASE):
        self.milter_expect_auth = True
    log_info("ENV[MILTER_EXPECT_AUTH]: {}".format(self.milter_expect_auth))
    
    if 'MILTER_WHITELISTED_RCPTS' in os.environ:
      # A blank separated list is expected
      whitelisted_rcpts_str = os.environ['MILTER_WHITELISTED_RCPTS']
      for whitelisted_rcpt in re.split(',|\s', whitelisted_rcpts_str):
        if g_rex_email.match(whitelisted_rcpt) == None:
          raise LamConfigBackendException(
            "ENV[MILTER_WHITELISTED_RCPTS]: invalid email address: {}"
            .format(whitelisted_rcpt)
          )
        else:
          self.milter_whitelisted_rcpts[whitelisted_rcpt] = {}
    log_info(
      "ENV[MILTER_WHITELISTED_RCPTS]: {}".format(
        self.milter_whitelisted_rcpts
      )
    )
    
    if 'MILTER_DKIM_ENABLED' in os.environ:
      self.milter_dkim_enabled = True
      if 'MILTER_TRUSTED_AUTHSERVID' in os.environ:
        self.milter_trusted_authservid = os.environ['MILTER_TRUSTED_AUTHSERVID'].lower()
        log_info(
          "ENV[MILTER_TRUSTED_AUTHSERVID]: {}".format(
            self.milter_trusted_authservid
          )
        )
      else:
        raise LamConfigBackendException("ENV[MILTER_TRUSTED_AUTHSERVID] is mandatory!")
    log_info("ENV[MILTER_DKIM_ENABLED]: {}".format(self.milter_dkim_enabled))
    
    if 'MILTER_MAX_RCPT_ENABLED' in os.environ:
      self.milter_max_rcpt_enabled = True
      if 'MILTER_MAX_RCPT' in os.environ:
        if os.environ['MILTER_MAX_RCPT'].isnumeric():
          self.milter_max_rcpt = int(os.environ['MILTER_MAX_RCPT'])
          log_info("ENV[MILTER_MAX_RCPT]: {}".format(self.milter_max_rcpt))
        else:
          raise LamConfigBackendException("ENV[MILTER_MAX_RCPT] must be numeric!")
    log_info("ENV[MILTER_MAX_RCPT_ENABLED]: {}".format(self.milter_max_rcpt_enabled))

    if 'MILTER_ALLOW_NULL_SENDER' in os.environ:
      if re.match(r'^true$', os.environ['MILTER_ALLOW_NULL_SENDER'], re.IGNORECASE):
        self.milter_allow_null_sender = True
    log_info("ENV[MILTER_ALLOW_NULL_SENDER]: {}".format(self.milter_allow_null_sender))
