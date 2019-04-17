import Milter
from ldap3 import (
  Server,ServerPool,Connection,NONE,LDAPOperationResult
)
import sys
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
g_re_domain = re.compile(r'^\S+@(\S+)$')
g_loglevel = logging.INFO
g_milter_mode = 'test'
g_milter_schema = False
g_milter_schema_wildcards = False # works only if g_milter_schema == True

class LdapAclMilter(Milter.Base):
  # Each new connection is handled in an own thread
  def __init__(self):
    self.time_start = timer()
    self.ldap_conn = g_ldap_conn
    self.client_addr = None
    self.env_from = None
    self.env_from_domain = None
    self.sasl_user = 'not_authenticated'
    # recipients list
    self.env_rcpts = []
    # https://stackoverflow.com/a/2257449
    self.mconn_id = g_milter_name + ': ' + ''.join(
      random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
    )

  # Not registered/used callbacks
  @Milter.nocallback
  def hello(self, heloname):
    return Milter.CONTINUE
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
      # this may fail, if no SASL authentication preceded
      sasl_user = self.getsymval('{auth_authen}')
      if sasl_user != None:
        self.sasl_user = sasl_user
      logging.debug(self.mconn_id + "/FROM sasl_user: " + self.sasl_user)
    except:
      logging.error(self.mconn_id + "/FROM " + str(sys.exc_info()))
    mailfrom = mailfrom.replace("<","")
    mailfrom = mailfrom.replace(">","")
    self.env_from = mailfrom
    m = g_re_domain.match(self.env_from)
    if m == None:
      logging.error(self.mconn_id + "/FROM " +
        "Could not determine domain of 5321.from: " + self.env_from
      )
      self.setreply('450','4.7.1', g_milter_tmpfail_message)
      return Milter.TEMPFAIL
    self.env_from_domain = m.group(1)
    logging.debug(self.mconn_id +
      "/FROM env_from_domain: " + self.env_from_domain
    )
    return Milter.CONTINUE

  def envrcpt(self, to, *str):
    time_start = timer()
    to = to.replace("<","")
    to = to.replace(">","")
    m = g_re_domain.match(to)
    if m == None:
      logging.error(self.mconn_id + "/RCPT " +
        "Could not determine domain of 5321.to: " + to
      )
      self.setreply('450','4.7.1', g_milter_tmpfail_message)
      return Milter.TEMPFAIL
    rcpt_domain = m.group(1)
    logging.debug(self.mconn_id +
      "/RCPT rcpt_domain: " + rcpt_domain
    )
    time_end = None
    try:
      if g_milter_schema == True:
        # LDAP-ACL-Milter own schema
        if g_milter_schema_wildcards == True:
          # TODO!
          pass
        else:
          # Authentication hierarchy!
          # 1. x509 client certificate
          # 2. SASL authenticated
          # if auth_type sasl_user, check if authenticated user matches sasl_user and
          # check if sender/recipient pair match
          # 3. Client-IP authenticated
          # if auth_type client_addr, check if client-ip matches client_addr
          # check if sender/recipient pair match
          # 4. not authenticated
          # ldap-search with excluded sasl_user and client_addr attributes!
          self.ldap_conn.search(g_ldap_base,
            "(&(allowedRcpts="+to+")(allowedSenders="+self.env_from+"))"
          )
          time_end = timer()
          if len(self.ldap_conn.entries) == 0:
            self.env_rcpts.append({
              "rcpt": to, "reason": g_milter_reject_message,
              "time_start":time_start, "time_end":time_end
            })
            if g_milter_mode == 'reject':
              logging.info(self.mconn_id + "/RCPT " + g_milter_reject_message)
              self.setreply('550','5.7.1',
                g_milter_reject_message + ' (' + self.mconn_id + ')'
              )
              return Milter.REJECT
            else:
              logging.info(self.mconn_id + "/RCPT TEST_MODE " +
                g_milter_reject_message
              )
              return Milter.CONTINUE
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
            "rcpt": to, "reason": g_milter_reject_message,
            "time_start":time_start, "time_end":time_end
          })
          if g_milter_mode == 'reject':
            logging.info(self.mconn_id + "/RCPT " + g_milter_reject_message)
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
    self.env_rcpts.append({
      "rcpt": to, "reason":'pass',"time_start":time_start,"time_end":time_end
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
          ": 5321.from=<" + self.env_from + "> 5321.rcpt=<" +
          rcpt['rcpt'] + "> reason: " + rcpt['reason'] +
          " duration: " + str(duration) + " sec."
        )
    except:
      logging.warn(self.mconn_id + "/DATA " + self.queue_id +
        ": " + str(sys.exc_info()))
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
    if 'MILTER_NAME' in os.environ:
      g_milter_name = os.environ['MILTER_NAME']
    if 'MILTER_SCHEMA' in os.environ:
      if re.match(r'^true$', os.environ['MILTER_SCHEMA'], re.IGNORECASE):
        g_milter_schema = True
        if 'MILTER_SCHEMA_WILDCARDS' in os.environ:
          if re.match(r'^true$', os.environ['MILTER_SCHEMA_WILDCARDS'], re.IGNORECASE):
            g_milter_schema_wildcards = True
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
    server = Server(g_ldap_server, get_info=NONE)
    g_ldap_conn = Connection(server,
      g_ldap_binddn, g_ldap_bindpw,
      auto_bind=True, raise_exceptions=True,
      client_strategy='RESTARTABLE'
    )
    logging.info("Connected to LDAP-server: " + g_ldap_server)
  except LDAPOperationResult as e:
    logging.error("LDAP Exception: " + str(e))
    sys.exit(1)
  try:
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
    logging.error("MAIN-EXCEPTION: " + str(sys.exc_info()))
