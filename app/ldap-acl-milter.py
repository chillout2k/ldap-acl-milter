from argparse import Action
import Milter
from ldap3 import (
  Server, Connection, NONE, set_config_parameter
)
from ldap3.core.exceptions import LDAPException
import sys
import traceback
import os
import logging
import string
import random
import re
from timeit import default_timer as timer
import email.utils
import authres

# Globals...
g_milter_name = 'ldap-acl-milter'
g_milter_socket = '/socket/' + g_milter_name
g_milter_reject_message = 'Security policy violation!'
g_milter_tmpfail_message = 'Service temporarily not available! Please try again later.'
g_ldap_conn = None
g_ldap_server = 'ldap://127.0.0.1:389'
g_ldap_binddn = 'cn=ldap-reader,ou=binds,dc=example,dc=org'
g_ldap_bindpw = 'TopSecret;-)'
g_ldap_base = 'ou=users,dc=example,dc=org'
g_ldap_query = '(&(mail=%rcpt%)(allowedEnvelopeSender=%from%))'
g_re_domain = re.compile(r'^\S*@(\S+)$')
# http://emailregex.com/ -> Python
g_re_email = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
g_loglevel = logging.INFO
g_milter_mode = 'test'
g_milter_default_policy = 'reject'
g_milter_schema = False
g_milter_schema_wildcard_domain = False # works only if g_milter_schema == True
g_milter_expect_auth = False
g_milter_whitelisted_rcpts = {}
g_milter_dkim_enabled = False
g_milter_trusted_authservid = None
g_re_srs = re.compile(r"^SRS0=.+=.+=(\S+)=(\S+)\@.+$")

class LamException(Exception):
  def __init__(self, message="General exception message"):
    self.message = message

class LamSoftException(LamException):
  pass

class LamHardException(LamException):
  pass

class LdapAclMilter(Milter.Base):
  # Each new connection is handled in an own thread
  def __init__(self):
    # client_addr gets overriden on any connect()
    self.client_addr = None

  def reset(self):
    self.proto_stage = 'proto-stage'
    self.env_from = None
    self.sasl_user = None
    self.x509_subject = None
    self.x509_issuer = None
    self.queue_id = 'invalid'
    self.env_rcpts = []
    self.hdr_from = None
    self.hdr_from_domain = None
    self.dkim_valid = False
    self.dkim_aligned = False
    self.passed_dkim_results = []
    logging.debug("reset(): {}".format(self.__dict__))
    # https://stackoverflow.com/a/2257449
    self.mconn_id = g_milter_name + ': ' + ''.join(
      random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
    )

  def milter_action(self, **kwargs):
    if 'action' not in kwargs:
      raise Exception("'action' kwarg is mandatory!")
    message = None
    smfir = None
    smtp_code = None
    smtp_ecode = None
    if kwargs['action'] == 'reject':
      message = g_milter_reject_message
      smtp_code = '550'
      smtp_ecode = '5.7.1'
      smfir = Milter.REJECT
    elif kwargs['action'] == 'tmpfail':
      message = g_milter_tmpfail_message
      smtp_code = '450'
      smtp_ecode = '4.7.1'
      smfir = Milter.TEMPFAIL
    elif kwargs['action'] == 'continue':
      message = 'continue'
      smfir = Milter.CONTINUE
    else:
      raise Exception("Invalid 'action': {}".format(kwargs['action']))
    # override message
    if 'message' in kwargs:
      message = kwargs['message']
    # prepend queue-id to message if it´s already available (DATA and later)
    if self.queue_id != 'invalid':
      message = " queue_id: {0} - {1}".format(self.queue_id, message)
    # append reason to message
    if 'reason' in kwargs:
      message = "{0} - reason: {1}".format(message, kwargs['reason'])
    if kwargs['action'] == 'reject' or kwargs['action'] == 'tmpfail':
      self.setreply(smtp_code, smtp_ecode, message)
      logging.info(self.mconn_id + "/" +
       self.proto_stage + ": milter_action={0} message={1}".format(kwargs['action'], message)
      )
    return smfir

  def check_policy(self, from_addr, rcpt_addr):
    logging.info(self.mconn_id +
      "/{0} from={1} rcpt={2}".format(
        self.proto_stage, from_addr, rcpt_addr
      )
    )
    m = g_re_domain.match(from_addr)
    if m == None:
      logging.info(self.mconn_id +
        "/{0} Could not determine domain of from={1}".format(
          self.proto_stage, from_addr
        )
      )
      raise LamSoftException()
    from_domain = m.group(1)
    logging.debug(self.mconn_id +
      "/{0} from_domain={1}".format(self.queue_id, from_domain)
    )
    m = g_re_domain.match(rcpt_addr)
    if m == None:
      raise LamSoftException("Could not determine domain of rcpt={}".format(rcpt_addr))
    rcpt_domain = m.group(1)
    logging.debug(self.mconn_id +
      "/{0} rcpt_domain={1}".format(self.queue_id, rcpt_domain)
    )
    try:
      if g_milter_schema == True:
        # LDAP-ACL-Milter schema
        auth_method = ''
        if g_milter_expect_auth == True:
          auth_method = "(|(allowedClientAddr="+self.client_addr+")%SASL_AUTH%%X509_AUTH%)"
          if self.sasl_user:
            auth_method = auth_method.replace(
              '%SASL_AUTH%',"(allowedSaslUser="+self.sasl_user+")"
            )
          else:
            auth_method = auth_method.replace('%SASL_AUTH%','')
          if self.x509_subject and self.x509_issuer:
            auth_method = auth_method.replace('%X509_AUTH%',
              "(&"+
                "(allowedx509subject="+self.x509_subject+")"+
                "(allowedx509issuer="+self.x509_issuer+")"+
              ")"
            )
          else:
            auth_method = auth_method.replace('%X509_AUTH%','')
          logging.debug(self.mconn_id +
            " auth_method: " + auth_method
          )
        if g_milter_schema_wildcard_domain == True:
          # The asterisk (*) character is in term of local part
          # RFC5322 compliant and expected as a wildcard literal in this code.
          # As the asterisk character is special in LDAP context, thus it must
          # be ASCII-HEX encoded '\2a' (42 in decimal => answer to everything)
          # for proper use in LDAP queries.
          # In this case *@<domain> cannot be a real address!
          if re.match(r'^\*@.+$', from_addr, re.IGNORECASE):
            raise LamHardException(
              "Literal wildcard sender (*@<domain>) is not " +
              "allowed in wildcard mode!"
            )
          if re.match(r'^\*@.+$', rcpt_addr, re.IGNORECASE):
            raise LamHardException(
              "Literal wildcard recipient (*@<domain>) is not " +
              "allowed in wildcard mode!"
            )
          g_ldap_conn.search(g_ldap_base,
            "(&" +
              auth_method +
              "(|"+
                "(allowedRcpts=" + rcpt_addr + ")"+
                "(allowedRcpts=\\2a@" + rcpt_domain + ")"+
                "(allowedRcpts=\\2a@\\2a)"+
              ")"+
              "(|"+
                "(allowedSenders=" + from_addr + ")"+
                "(allowedSenders=\\2a@" + from_domain + ")"+
                "(allowedSenders=\\2a@\\2a)"+
              ")"+
            ")",
            attributes=['policyID']
          )
        else:
          # Wildcard-domain DISABLED
          # Asterisk must be ASCII-HEX encoded for LDAP queries
          query_from = from_addr.replace("*","\\2a")
          query_to = rcpt_addr.replace("*","\\2a")
          g_ldap_conn.search(g_ldap_base,
            "(&" +
              auth_method +
              "(allowedRcpts=" + query_to + ")" +
              "(allowedSenders=" + query_from + ")" +
            ")",
            attributes=['policyID']
          )
        if len(g_ldap_conn.entries) == 0:
          # Policy not found in LDAP
          if g_milter_expect_auth == True:
            logging.info(self.mconn_id + " " + "policy mismatch "
              "from=" + from_addr + ", rcpt=" + rcpt_addr +
              ", auth_method=" + auth_method
            )
          else:
            logging.info(self.mconn_id + " " + "policy mismatch "
              "from=" + from_addr + ", rcpt=" + rcpt_addr
            )
          if g_milter_mode == 'reject':
            raise LamHardException("policy not found!")
          else:
            logging.info(self.mconn_id + " TEST_MODE " +
              g_milter_reject_message
            )
        elif len(g_ldap_conn.entries) == 1:
          # Policy found in LDAP, but which one?
          entry = g_ldap_conn.entries[0]
          logging.info(self.mconn_id +
            "/{0} Policy match: {1}".format(self.proto_stage, entry.policyID.value)
          )
        elif len(g_ldap_conn.entries) > 1:
          # Something went wrong!? There shouldn´t be more than one entries!
          logging.warning(self.mconn_id + " More than one policies found! "+
            "from=" + from_addr + ", rcpt=" + rcpt_addr +
            ", auth_method=" + auth_method
          )
          raise LamHardException("More than one policies found!")
      else:
        # Custom LDAP schema
        # 'build' a LDAP query per recipient
        # replace all placeholders in query templates
        query = g_ldap_query.replace("%rcpt%", rcpt_addr)
        query = query.replace("%from%", from_addr)
        query = query.replace("%client_addr%", self.client_addr)
        query = query.replace("%sasl_user%", self.sasl_user)
        query = query.replace("%from_domain%", from_domain)
        query = query.replace("%rcpt_domain%", rcpt_domain)
        logging.debug(self.mconn_id + " " + query)
        g_ldap_conn.search(g_ldap_base, query)
        if len(g_ldap_conn.entries) == 0:
          logging.info(self.mconn_id + " " + "policy mismatch "
            "from: " + from_addr + " and rcpt: " + rcpt_addr
          )
          if g_milter_mode == 'reject':
            raise LamHardException("policy mismatch")
          else:
            logging.info(self.mconn_id + " TEST_MODE " +
              g_milter_reject_message
            )
    except LDAPException as e:
      logging.error(self.mconn_id + " LDAP: " + str(e))
      raise LamSoftException(" LDAP: " + str(e)) from e;
    return self.milter_action(action = 'continue')

  # Not registered/used callbacks
  @Milter.nocallback
  def eoh(self):
    return self.milter_action(action = 'continue')
  @Milter.nocallback
  def body(self, chunk):
    return self.milter_action(action = 'continue')

  def connect(self, IPname, family, hostaddr):
    self.reset()
    self.proto_stage = 'CONNECT'
    self.client_addr = hostaddr[0]
    logging.debug(self.mconn_id +
      "/CONNECT client_addr=[" + self.client_addr + "]:" + str(hostaddr[1])
    )
    return self.milter_action(action = 'continue')

  def envfrom(self, mailfrom, *str):
    self.reset()
    self.proto_stage = 'FROM'
    if g_milter_expect_auth:
      try:
        # this may fail, if no x509 client certificate was used.
        # postfix only passes this macro to milters if the TLS connection
        # with the authenticating client was trusted in a x509 manner!
        # http://postfix.1071664.n5.nabble.com/verification-levels-and-Milter-tp91634p91638.html
        # Unfortunately, postfix only passes the CN-field of the subject/issuer DN :-/
        x509_subject = self.getsymval('{cert_subject}')
        if x509_subject != None:
          self.x509_subject = x509_subject
          logging.debug(self.mconn_id + "/FROM x509_subject=" + self.x509_subject)
        else:
          logging.debug(self.mconn_id + "/FROM No x509_subject registered")
        x509_issuer = self.getsymval('{cert_issuer}')
        if x509_issuer != None:
          self.x509_issuer = x509_issuer
          logging.debug(self.mconn_id + "/FROM x509_issuer=" + self.x509_issuer)
        else:
          logging.debug(self.mconn_id + "/FROM No x509_issuer registered")
      except:
        logging.error(self.mconn_id + "/FROM x509 " + traceback.format_exc())
      try:
        # this may fail, if no SASL authentication preceded
        sasl_user = self.getsymval('{auth_authen}')
        if sasl_user != None:
          self.sasl_user = sasl_user
          logging.debug(self.mconn_id + "/FROM sasl_user=" + self.sasl_user)
        else:
          logging.debug(self.mconn_id + "/FROM No sasl_user registered")
      except:
        logging.error(self.mconn_id + "/FROM sasl_user " + traceback.format_exc())
      logging.info(self.mconn_id + "/FROM auth: " + 
        "client_ip={0}, x509_subject={1}, x509_issuer={2}, sasl_user={3}".format(
          self.client_addr, self.x509_subject, self.x509_issuer, self.sasl_user
        )
      )
    mailfrom = mailfrom.replace("<","")
    mailfrom = mailfrom.replace(">","")
    # BATV (https://tools.ietf.org/html/draft-levine-smtp-batv-01)
    # Strip out Simple Private Signature (PRVS)
    mailfrom = re.sub(r"^prvs=.{10}=", '', mailfrom)
    # SRS (https://www.libsrs2.org/srs/srs.pdf)
    m_srs = g_re_srs.match(mailfrom)
    if m_srs != None:
      logging.info(self.mconn_id + "/FROM " +
        "Found SRS-encoded envelope-sender: " + mailfrom
      )
      mailfrom = m_srs.group(2) + '@' + m_srs.group(1)
      logging.info(self.mconn_id + "/FROM " +
        "SRS envelope-sender replaced with: " + mailfrom
      )
    self.env_from = mailfrom.lower()
    logging.debug(self.mconn_id + "/FROM 5321.from={}".format(self.env_from))
    m = g_re_domain.match(self.env_from)
    if m == None:
      return self.milter_action(
        action = 'tmpfail',
        reason = "Could not determine domain of 5321.from=" + self.env_from
      )
    return self.milter_action(action = 'continue')

  def envrcpt(self, to, *str):
    self.proto_stage = 'RCPT'
    to = to.replace("<","")
    to = to.replace(">","")
    to = to.lower()
    logging.debug(self.mconn_id +
      "/RCPT env_rcpt={}".format(to)
    )
    if to in g_milter_whitelisted_rcpts:
      return self.milter_action(action = 'continue')
    if g_milter_dkim_enabled:
      # Collect all envelope-recipients for later
      # investigation (EOM). Do not perform any 
      # policy action at this protocol phase.
      self.env_rcpts.append(to)
    else:
      try:
        return self.check_policy(self.env_from, to)
      except LamSoftException as e:
        return self.milter_action(action = 'tmpfail')
      except LamHardException as e:
        return self.milter_action(
          action = 'reject',
          reason = e.message
        )
    return self.milter_action(action = 'continue')

  def header(self, hname, hval):
    self.proto_stage = 'HDR'
    self.queue_id = self.getsymval('i')
    if g_milter_dkim_enabled == True:
      # Parse RFC-5322-From header
      if(hname.lower() == "From".lower()):
        hdr_5322_from = email.utils.parseaddr(hval)
        self.hdr_from = hdr_5322_from[1].lower()
        m = re.match(g_re_domain, self.hdr_from)
        if m is None:
          return self.milter_action(
            action = 'reject',
            reason = "Could not determine domain-part of 5322.from=" + self.hdr_from
          )
        self.hdr_from_domain = m.group(1)
        logging.info(self.mconn_id + "/" + str(self.queue_id) +
          "/HDR: 5322.from={0}, 5322.from_domain={1}".format(
            self.hdr_from, self.hdr_from_domain
          )
        )
      # Parse RFC-7601 Authentication-Results header
      elif(hname.lower() == "Authentication-Results".lower()):
        ar = None
        try:
          ar = authres.AuthenticationResultsHeader.parse(
            "{0}: {1}".format(hname, hval)
          )
          if ar.authserv_id.lower() == g_milter_trusted_authservid.lower():
            for ar_result in ar.results:
              if ar_result.method.lower() == 'dkim':
                if ar_result.result.lower() == 'pass':
                  self.passed_dkim_results.append(ar_result.header_d.lower())
                  logging.debug(self.mconn_id + "/" + str(self.queue_id) +
                    "/HDR: dkim=pass sdid={0}".format(ar_result.header_d)
                  )
                  self.dkim_valid = True
          else:
            logging.debug(self.mconn_id + "/" + str(self.queue_id) +
              "/HDR: Ignoring authentication results of {0}".format(ar.authserv_id)
            )
        except Exception as e:
          logging.info(self.mconn_id + "/" + str(self.queue_id) +
            "/HDR: AR-parse exception: {0}".format(str(e))
          )
    return self.milter_action(action = 'continue')

  def eom(self):
    self.proto_stage = 'EOM'
    if g_milter_dkim_enabled:
      if self.dkim_valid:
        # There is at least one valid DKIM signature!
        # Check if one of them is also aligned
        for passed_dkim_sdid in self.passed_dkim_results:
          if self.hdr_from_domain.lower() == passed_dkim_sdid.lower():
            self.dkim_aligned = True
            logging.info(self.mconn_id + "/" + str(self.queue_id) +
              "/EOM: Found aligned DKIM signature for SDID: {0}".format(
                passed_dkim_sdid
              ) 
            )
      reject_message = False
      for rcpt in self.env_rcpts:
        try:
          # Check 5321.sender against policy
          self.check_policy(self.env_from, rcpt)
        except LamSoftException as e:
          return self.milter_action(action = 'tmpfail')
        except LamHardException as e:
          if self.dkim_aligned:
            try:
              # Check 5322.sender against policy
              self.check_policy(self.hdr_from, rcpt)
              logging.info(self.mconn_id +
                "/{0}/{1} from={2} authorized by DKIM signature".format(
                  self.queue_id, self.proto_stage, self.hdr_from
                )
              )
            except LamHardException as e:
              reject_message = True
          else:
            reject_message = True

        if reject_message:
          return self.milter_action(
            action = 'reject',
            reason = 'EOM - Policy mismatch! All recipients were rejected!'
          )
    return self.milter_action(action = 'continue')

  def abort(self):
    # Client disconnected prematurely
    self.proto_stage = 'ABORT'
    return self.milter_action(action = 'continue')

  def close(self):
    # Always called, even when abort is called.
    # Clean up any external resources here.
    self.proto_stage = 'CLOSE'
    return self.milter_action(action = 'continue')

if __name__ == "__main__":
  try:
    if 'LOG_LEVEL' in os.environ:
      if re.match(r'^info$', os.environ['LOG_LEVEL'], re.IGNORECASE):
        g_loglevel = logging.INFO
      elif re.match(r'^warn|warning$', os.environ['LOG_LEVEL'], re.IGNORECASE):
        g_loglevel = logging.WARN
      elif re.match(r'^error$', os.environ['LOG_LEVEL'], re.IGNORECASE):
        g_loglevel = logging.ERROR
      elif re.match(r'debug', os.environ['LOG_LEVEL'], re.IGNORECASE):
        g_loglevel = logging.DEBUG
    logging.basicConfig(
      filename=None, # log to stdout
      format='%(asctime)s: %(levelname)s %(message)s',
      level=g_loglevel
    )
    if 'MILTER_MODE' in os.environ:
      if re.match(r'^test|reject$',os.environ['MILTER_MODE'], re.IGNORECASE):
        g_milter_mode = os.environ['MILTER_MODE']
    if 'MILTER_DEFAULT_POLICY' in os.environ:
      if re.match(r'^reject|permit$',os.environ['MILTER_DEFAULT_POLICY'], re.IGNORECASE):
        g_milter_default_policy = str(os.environ['MILTER_DEFAULT_POLICY']).lower()
      else:
        logging.warning("MILTER_DEFAULT_POLICY invalid value: " +
          os.environ['MILTER_DEFAULT_POLICY']
        )
    if 'MILTER_NAME' in os.environ:
      g_milter_name = os.environ['MILTER_NAME']
    if 'MILTER_SCHEMA' in os.environ:
      if re.match(r'^true$', os.environ['MILTER_SCHEMA'], re.IGNORECASE):
        g_milter_schema = True
        if 'MILTER_SCHEMA_WILDCARD_DOMAIN' in os.environ:
          if re.match(r'^true$', os.environ['MILTER_SCHEMA_WILDCARD_DOMAIN'], re.IGNORECASE):
            g_milter_schema_wildcard_domain = True
    if 'LDAP_SERVER' not in os.environ:
      logging.error("Missing ENV[LDAP_SERVER], e.g. " + g_ldap_server)
      sys.exit(1)
    g_ldap_server = os.environ['LDAP_SERVER']
    if 'LDAP_BINDDN' in os.environ:
      g_ldap_binddn = os.environ['LDAP_BINDDN']
    if 'LDAP_BINDPW' in os.environ:
      g_ldap_bindpw = os.environ['LDAP_BINDPW']
    if 'LDAP_BASE' not in os.environ:
      logging.error("Missing ENV[LDAP_BASE], e.g. " + g_ldap_base)
      sys.exit(1)
    g_ldap_base = os.environ['LDAP_BASE']
    if 'LDAP_QUERY' not in os.environ:
      if g_milter_schema == False:
        logging.error(
          "ENV[MILTER_SCHEMA] is disabled and ENV[LDAP_QUERY] is not set instead!"
        )
        sys.exit(1)
    if 'LDAP_QUERY' in os.environ:
      g_ldap_query = os.environ['LDAP_QUERY']
    if 'MILTER_SOCKET' in os.environ:
      g_milter_socket = os.environ['MILTER_SOCKET']
    if 'MILTER_REJECT_MESSAGE' in os.environ:
      g_milter_reject_message = os.environ['MILTER_REJECT_MESSAGE']
    if 'MILTER_TMPFAIL_MESSAGE' in os.environ:
      g_milter_tmpfail_message = os.environ['MILTER_TMPFAIL_MESSAGE']
    if 'MILTER_EXPECT_AUTH' in os.environ:
      if re.match(r'^true$', os.environ['MILTER_EXPECT_AUTH'], re.IGNORECASE):
        g_milter_expect_auth = True
    if 'MILTER_WHITELISTED_RCPTS' in os.environ:
      # A blank separated list is expected
      whitelisted_rcpts_str = os.environ['MILTER_WHITELISTED_RCPTS']
      for whitelisted_rcpt in re.split(',|\s', whitelisted_rcpts_str):
        if g_re_email.match(whitelisted_rcpt) == None:
          logging.error(
            "ENV[MILTER_WHITELISTED_RCPTS]: invalid email address: " +
            whitelisted_rcpt
          )
          sys.exit(1)
        else:
          logging.info("ENV[MILTER_WHITELISTED_RCPTS]: " + whitelisted_rcpt)
          g_milter_whitelisted_rcpts[whitelisted_rcpt] = {}
    if 'MILTER_DKIM_ENABLED' in os.environ:
      g_milter_dkim_enabled = True
      if 'MILTER_TRUSTED_AUTHSERVID' in os.environ:
        g_milter_trusted_authservid = os.environ['MILTER_TRUSTED_AUTHSERVID'].lower()
        logging.info("ENV[MILTER_TRUSTED_AUTHSERVID]: {0}".format(g_milter_trusted_authservid))
      else:
        logging.error("ENV[MILTER_TRUSTED_AUTHSERVID] is mandatory!")
        sys.exit(1)
    logging.info("ENV[MILTER_DKIM_ENABLED]: {0}".format(g_milter_dkim_enabled))
    set_config_parameter("RESTARTABLE_SLEEPTIME", 2)
    set_config_parameter("RESTARTABLE_TRIES", 2)
    server = Server(g_ldap_server, get_info=NONE)
    g_ldap_conn = Connection(server,
      g_ldap_binddn, g_ldap_bindpw,
      auto_bind=True, raise_exceptions=True,
      client_strategy='RESTARTABLE'
    )
    logging.info("Connected to LDAP-server: " + g_ldap_server)
    timeout = 600
    # Register to have the Milter factory create instances of your class:
    Milter.factory = LdapAclMilter
    # Tell the MTA which features we use
    flags = Milter.ADDHDRS
    Milter.set_flags(flags)
    logging.info("Startup " + g_milter_name +
      "@socket: " + g_milter_socket +
      " in mode: " + g_milter_mode
    )
    Milter.runmilter(g_milter_name,g_milter_socket,timeout,True)
    logging.info("Shutdown " + g_milter_name)
  except:
    logging.error("MAIN-EXCEPTION: " + traceback.format_exc())
    sys.exit(1)
