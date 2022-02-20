import re
import os
from lam_rex import rex_email
from lam_logger import log_info

class LamConfigException(Exception):
  def __init__(self, message):
    self.message = message
  def __str__(self):
    return self.message

class LamConfig():
  def __init__(self):
    self.milter_mode = 'test'
    self.milter_name = 'ldap-acl-milter'
    self.milter_socket = '/socket/{}'.format(self.milter_name)
    self.milter_reject_message = 'Security policy violation!'
    self.milter_tmpfail_message = 'Service temporarily not available! Please try again later.'
    self.ldap_server = 'ldap://127.0.0.1:389'
    self.ldap_binddn = 'cn=ldap-reader,ou=binds,dc=example,dc=org'
    self.ldap_bindpw = 'TopSecret;-)'
    self.ldap_base = 'ou=lam,ou=services,dc=example,dc=org'
    self.ldap_query = '(&(mail=%rcpt%)(allowedEnvelopeSender=%from%))'
    self.milter_schema = False
    self.milter_schema_wildcard_domain = False # works only if milter_schema == True
    self.milter_expect_auth = False
    self.milter_whitelisted_rcpts = {}
    self.milter_dkim_enabled = False
    self.milter_trusted_authservid = None
    self.milter_max_rcpt_enabled = False
    self.milter_max_rcpt = 1

    if 'MILTER_MODE' in os.environ:
      if re.match(r'^test|reject$',os.environ['MILTER_MODE'], re.IGNORECASE):
        self.milter_mode = os.environ['MILTER_MODE'].lower()
    if 'MILTER_NAME' in os.environ:
      self.milter_name = os.environ['MILTER_NAME']
    if 'MILTER_SCHEMA' in os.environ:
      if re.match(r'^true$', os.environ['MILTER_SCHEMA'], re.IGNORECASE):
        self.milter_schema = True
        if 'MILTER_SCHEMA_WILDCARD_DOMAIN' in os.environ:
          if re.match(r'^true$', os.environ['MILTER_SCHEMA_WILDCARD_DOMAIN'], re.IGNORECASE):
            self.milter_schema_wildcard_domain = True
    if 'LDAP_SERVER' not in os.environ:
      raise LamConfigException("Missing ENV[LDAP_SERVER], e.g. {}".format(self.ldap_server))
    self.ldap_server = os.environ['LDAP_SERVER']
    if 'LDAP_BINDDN' in os.environ:
      self.ldap_binddn = os.environ['LDAP_BINDDN']
    if 'LDAP_BINDPW' in os.environ:
      self.ldap_bindpw = os.environ['LDAP_BINDPW']
    if 'LDAP_BASE' not in os.environ:
      raise LamConfigException(
        "Missing ENV[LDAP_BASE], e.g. {}".format(self.ldap_base)
      )
    self.ldap_base = os.environ['LDAP_BASE']
    if 'LDAP_QUERY' not in os.environ:
      if self.milter_schema == False:
        raise LamConfigException(
          "ENV[MILTER_SCHEMA] is disabled and ENV[LDAP_QUERY] is not set instead!"
        )
    if 'LDAP_QUERY' in os.environ:
      self.ldap_query = os.environ['LDAP_QUERY']
    if 'MILTER_SOCKET' in os.environ:
      self.milter_socket = os.environ['MILTER_SOCKET']
    if 'MILTER_REJECT_MESSAGE' in os.environ:
      self.milter_reject_message = os.environ['MILTER_REJECT_MESSAGE']
    if 'MILTER_TMPFAIL_MESSAGE' in os.environ:
      self.milter_tmpfail_message = os.environ['MILTER_TMPFAIL_MESSAGE']
    if 'MILTER_EXPECT_AUTH' in os.environ:
      if re.match(r'^true$', os.environ['MILTER_EXPECT_AUTH'], re.IGNORECASE):
        self.milter_expect_auth = True
    if 'MILTER_WHITELISTED_RCPTS' in os.environ:
      # A blank separated list is expected
      whitelisted_rcpts_str = os.environ['MILTER_WHITELISTED_RCPTS']
      for whitelisted_rcpt in re.split(',|\s', whitelisted_rcpts_str):
        if rex_email.match(whitelisted_rcpt) == None:
          raise LamConfigException(
            "ENV[MILTER_WHITELISTED_RCPTS]: invalid email address: {}"
            .format(whitelisted_rcpt)
          )
        else:
          log_info("ENV[MILTER_WHITELISTED_RCPTS]: {}".format(
            whitelisted_rcpt
          ))
          self.milter_whitelisted_rcpts[whitelisted_rcpt] = {}
    if 'MILTER_DKIM_ENABLED' in os.environ:
      self.milter_dkim_enabled = True
      if 'MILTER_TRUSTED_AUTHSERVID' in os.environ:
        self.milter_trusted_authservid = os.environ['MILTER_TRUSTED_AUTHSERVID'].lower()
        log_info("ENV[MILTER_TRUSTED_AUTHSERVID]: {0}".format(
          self.milter_trusted_authservid
        ))
      else:
        raise LamConfigException("ENV[MILTER_TRUSTED_AUTHSERVID] is mandatory!")
    log_info("ENV[MILTER_DKIM_ENABLED]: {0}".format(self.milter_dkim_enabled))
    if 'MILTER_MAX_RCPT_ENABLED' in os.environ:
      self.milter_max_rcpt_enabled = True
      if 'MILTER_MAX_RCPT' in os.environ:
        if os.environ['MILTER_MAX_RCPT'].isnumeric():
          self.milter_max_rcpt = os.environ['MILTER_MAX_RCPT']
        else:
          raise LamConfigException("ENV[MILTER_MAX_RCPT] must be numeric!")


