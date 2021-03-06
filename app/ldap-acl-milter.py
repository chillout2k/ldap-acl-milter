import Milter
from ldap3 import (
  Server,ServerPool,Connection,NONE,LDAPOperationResult,set_config_parameter
)
import sys
import traceback
import os
import logging
import string
import random
import re
from timeit import default_timer as timer

# Globals...
g_milter_name = 'ldap-acl-milter'
g_milter_socket = '/socket/' + g_milter_name
g_milter_reject_message = 'Security policy violation!'
g_milter_tmpfail_message = 'Service temporarily not available! Please try again later.'
g_ldap_conn = None
# ...with mostly senseless defaults ;)
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
g_re_srs = re.compile(r"^SRS0=.+=.+=(\S+)=(\S+)\@.+$")

class LdapAclMilter(Milter.Base):
  # Each new connection is handled in an own thread
  def __init__(self):
    self.time_start = timer()
    self.ldap_conn = g_ldap_conn
    self.client_addr = None
    self.env_from = None
    self.env_from_domain = None
    self.sasl_user = None
    self.x509_subject = None
    self.x509_issuer = None
    # recipients list
    self.env_rcpts = []
    # https://stackoverflow.com/a/2257449
    self.mconn_id = g_milter_name + ': ' + ''.join(
      random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
    )

  # Not registered/used callbacks
  #@Milter.nocallback
  #def hello(self, heloname)
  #  return Milter.CONTINUE
  @Milter.nocallback
  def header(self, name, hval):
    return Milter.CONTINUE
  @Milter.nocallback
  def eoh(self):
    return Milter.CONTINUE
  @Milter.nocallback
  def body(self, chunk):
    return Milter.CONTINUE

  def connect(self, IPname, family, hostaddr):
    self.client_addr = hostaddr[0]
    logging.debug(self.mconn_id +
      "/CONNECT client_addr=[" + self.client_addr + "]:" + str(hostaddr[1])
    )
    return Milter.CONTINUE

  def envfrom(self, mailfrom, *str):
    try:
      # this may fail, if no x509 client certificate was used.
      # postfix only passes this macro to milters if the TLS connection
      # with the authenticating client was trusted in a x509 manner!
      # http://postfix.1071664.n5.nabble.com/verification-levels-and-Milter-tp91634p91638.html
      # Unfortunately, postfix only passes the CN-field of the subject/issuer DN :-/
      x509_subject = self.getsymval('{cert_subject}')
      if x509_subject != None:
        self.x509_subject = x509_subject
        logging.info(self.mconn_id + "/FROM x509_subject=" + self.x509_subject)
      x509_issuer = self.getsymval('{cert_issuer}')
      if x509_issuer != None:
        self.x509_issuer = x509_issuer
        logging.info(self.mconn_id + "/FROM x509_issuer=" + self.x509_issuer)
    except:
      logging.error(self.mconn_id + "/FROM x509 " + traceback.format_exc())
    try:
      # this may fail, if no SASL authentication preceded
      sasl_user = self.getsymval('{auth_authen}')
      if sasl_user != None:
        self.sasl_user = sasl_user
        logging.info(self.mconn_id + "/FROM sasl_user=" + self.sasl_user)
    except:
      logging.error(self.mconn_id + "/FROM sasl_user " + traceback.format_exc())
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
    self.env_from = mailfrom
    m = g_re_domain.match(self.env_from)
    if m == None:
      logging.error(self.mconn_id + "/FROM " +
        "Could not determine domain of 5321.from=" + self.env_from
      )
      self.setreply('450','4.7.1', g_milter_tmpfail_message)
      return Milter.TEMPFAIL
    self.env_from_domain = m.group(1)
    logging.debug(self.mconn_id +
      "/FROM env_from_domain=" + self.env_from_domain
    )
    return Milter.CONTINUE

  def envrcpt(self, to, *str):
    time_start = timer()
    to = to.replace("<","")
    to = to.replace(">","")
    if to in g_milter_whitelisted_rcpts:
      time_end = timer()
      self.env_rcpts.append({
        "rcpt": to, "action":'whitelisted_rcpt',"time_start":time_start,"time_end":time_end
      })
      return Milter.CONTINUE
    m = g_re_domain.match(to)
    if m == None:
      logging.error(self.mconn_id + "/RCPT " +
        "Could not determine domain of 5321.to: " + to
      )
      self.setreply('450','4.7.1', g_milter_tmpfail_message)
      return Milter.TEMPFAIL
    rcpt_domain = m.group(1)
    logging.debug(self.mconn_id +
      "/RCPT rcpt_domain=" + rcpt_domain
    )
    time_end = None
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
          if re.match(r'^\*@.+$', self.env_from, re.IGNORECASE):
            logging.info(self.mconn_id + "/RCPT REJECT " +
              "Literal wildcard sender (*@<domain>) is not " +
              "allowed in wildcard mode!"
            )
            self.setreply('550','5.7.1',
              g_milter_reject_message + ' (' + self.mconn_id + ')'
            )
            return Milter.REJECT
          if re.match(r'^\*@.+$', to, re.IGNORECASE):
            logging.info(self.mconn_id + "/RCPT REJECT " +
              "Literal wildcard recipient (*@<domain>) is not " +
              "allowed in wildcard mode!"
            )
            self.setreply('550','5.7.1',
              g_milter_reject_message + ' (' + self.mconn_id + ')'
            )
            return Milter.REJECT
          self.ldap_conn.search(g_ldap_base,
            "(&" +
              auth_method +
              "(|"+
                "(allowedRcpts="+to+")"+
                "(allowedRcpts=\\2a@"+rcpt_domain+")"+
                "(allowedRcpts=\\2a@\\2a)"+
              ")"+
              "(|"+
                "(allowedSenders="+self.env_from+")"+
                "(allowedSenders=\\2a@"+self.env_from_domain+")"+
                "(allowedSenders=\\2a@\\2a)"+
              ")"+
            ")",
            attributes=['policyID']
          )
        else:
          # Asterisk must be ASCII-HEX encoded for LDAP queries
          query_from = self.env_from.replace("*","\\2a")
          query_to = to.replace("*","\\2a")
          self.ldap_conn.search(g_ldap_base,
            "(&" +
              auth_method +
              "(allowedRcpts="+query_to+")" +
              "(allowedSenders="+query_from+")" +
            ")",
            attributes=['policyID']
          )
        time_end = timer()
        if len(self.ldap_conn.entries) == 0:
          # Policy not found in LDAP
          self.env_rcpts.append({
            "rcpt": to, "action": g_milter_reject_message,
            "time_start":time_start, "time_end":time_end
          })
          if g_milter_expect_auth == True:
            logging.info(self.mconn_id + "/RCPT " + "policy mismatch "
              "5321.from=" + self.env_from + ", 5321.rcpt=" + to +
              ", auth_method=" + auth_method
            )
          else:
            logging.info(self.mconn_id + "/RCPT " + "policy mismatch "
              "5321.from=" + self.env_from + ", 5321.rcpt=" + to
            )
          if g_milter_mode == 'reject':
            logging.info(self.mconn_id + "/RCPT REJECT "
              + g_milter_reject_message
            )
            self.setreply('550','5.7.1',
              g_milter_reject_message + ' (' + self.mconn_id + ')'
            )
            return Milter.REJECT
          else:
            logging.info(self.mconn_id + "/RCPT TEST_MODE " +
              g_milter_reject_message
            )
            return Milter.CONTINUE
        elif len(self.ldap_conn.entries) == 1:
          # Policy found in LDAP, but which one?
          entry = self.ldap_conn.entries[0]
          logging.info(self.mconn_id +
            "/RCPT Policy match: " + entry.policyID.value
          )
        elif len(self.ldap_conn.entries) > 1:
          # Something went wrong!? There shouldn´t be more than one entries!
          logging.warn(self.mconn_id + "/RCPT More than one policies found! "+
             "5321.from=" + self.env_from + ", 5321.rcpt=" + to +
             ", auth_method=" + auth_method
          )
          self.setreply('550','5.7.1',
            g_milter_reject_message + ' (' + self.mconn_id + ')'
          )
          return Milter.REJECT
      else:
        # Custom LDAP schema
        # 'build' a LDAP query per recipient
        # replace all placeholders in query templates
        query = g_ldap_query.replace("%rcpt%",to)
        query = query.replace("%from%", self.env_from)
        query = query.replace("%client_addr%", self.client_addr)
        query = query.replace("%sasl_user%", self.sasl_user)
        query = query.replace("%from_domain%", self.env_from_domain)
        query = query.replace("%rcpt_domain%", rcpt_domain)
        logging.debug(self.mconn_id + "/RCPT " + query)
        self.ldap_conn.search(g_ldap_base, query)
        time_end = timer()
        if len(self.ldap_conn.entries) == 0:
          self.env_rcpts.append({
            "rcpt": to, "action": g_milter_reject_message,
            "time_start":time_start, "time_end":time_end
          })
          logging.info(self.mconn_id + "/RCPT " + "policy mismatch "
            "5321.from: " + self.env_from + " and 5321.rcpt: " + to
          )
          if g_milter_mode == 'reject':
            logging.info(self.mconn_id + "/RCPT REJECT " + g_milter_reject_message)
            self.setreply('550','5.7.1',
              g_milter_reject_message + ' (' + self.mconn_id + ')'
            )
            return Milter.REJECT
          else:
            logging.info(self.mconn_id + "/RCPT TEST_MODE " +
              g_milter_reject_message
            )
            return Milter.CONTINUE
    except LDAPOperationResult as e:
      logging.warn(self.mconn_id + "/RCPT LDAP: " + str(e))
      self.setreply('451', '4.7.1', g_milter_tmpfail_message)
      return Milter.TEMPFAIL
    except:
      logging.error(self.mconn_id + "/RCPT LDAP: " + traceback.format_exc())
      self.setreply('451', '4.7.1', g_milter_tmpfail_message)
      return Milter.TEMPFAIL
    self.env_rcpts.append({
      "rcpt": to, "action":'pass',"time_start":time_start,"time_end":time_end
    })
    return Milter.CONTINUE

  def data(self):
    # A queue-id will be generated after the first accepted RCPT TO
    # and therefore not available until DATA command
    self.queue_id = self.getsymval('i')
    try:
      for rcpt in self.env_rcpts:
        duration = rcpt['time_end'] - rcpt['time_start']
        logging.info(self.mconn_id + "/DATA " + self.queue_id +
          ": 5321.from=" + self.env_from + " 5321.rcpt=" +
          rcpt['rcpt'] + " action=" + rcpt['action'] +
          " duration=" + str(duration) + "sec."
        )
    except:
      logging.warn(self.mconn_id + "/DATA " + self.queue_id +
        ": " + traceback.format_exc())
      self.setreply('451', '4.7.1', g_milter_tmpfail_message)
      return Milter.TEMPFAIL
    return Milter.CONTINUE

  def eom(self):
    # EOM is not optional and thus, always called by MTA
    time_end = timer()
    duration = time_end - self.time_start
    logging.info(self.mconn_id + "/EOM " + self.queue_id +
      " processed in " + str(duration) + " sec."
    )
    return Milter.CONTINUE

  def abort(self):
    # Client disconnected prematurely
    return Milter.CONTINUE

  def close(self):
    # Always called, even when abort is called.
    # Clean up any external resources here.
    return Milter.CONTINUE

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
        logging.warn("MILTER_DEFAULT_POLICY invalid value: " +
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
#      for whitelisted_rcpt in whitelisted_rcpts_str.split():
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
