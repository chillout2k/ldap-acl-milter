import Milter
from ldap3 import Server,Connection,NONE,LDAPOperationResult
import sys
import os
import logging
from timeit import default_timer as timer
from multiprocessing import Process,Queue

log_queue = Queue(maxsize=4)
g_milter_name = 'ldap-acl-milter'
g_milter_socket = '/socket/' + g_milter_name
g_milter_reject_message = 'Absender/Empfaenger passen nicht!'
g_ldap_conn = None
g_ldap_server = 'ldap://127.0.0.1:389'
g_ldap_binddn = 'cn=ldap-reader,ou=binds,dc=example,dc=org'
g_ldap_bindpw = 'TopSecret;-)'
g_ldap_base = 'ou=users,dc=example,dc=org'
g_ldap_query = '(&(mail=%rcpt%)(allowedEnvelopeSender=%from%))'
logging.basicConfig(
  filename=None, # log to stdout
  format='%(asctime)s: %(levelname)s %(message)s',
  level=logging.INFO
)

class LdapAclMilter(Milter.Base):
  def __init__(self):  # A new instance with each new connection.
    self.time_start = timer()
    self.id = Milter.uniqueID()
    self.ldap_conn = g_ldap_conn
    self.R = []

  # Not registered callbacks
  @Milter.nocallback
  def connect(self, IPname, family, hostaddr):
    return self.CONTINUE
  @Milter.nocallback
  def hello(self, heloname):
    return self.CONTINUE
  @Milter.nocallback
  def header(self, name, hval):
    return self.CONTINUE
  @Milter.nocallback
  def eoh(self):
    return self.CONTINUE
  @Milter.nocallback
  def body(self, chunk):
    return self.CONTINUE

  def envfrom(self, mailfrom, *str):
    if mailfrom == '<>':
      self.setreply('550','5.7.1','Envelope null-sender not allowed!')
      Milter.REJECT
    mailfrom = mailfrom.replace("<","")
    mailfrom = mailfrom.replace(">","")
    self.F = mailfrom
    return Milter.CONTINUE

  def envrcpt(self, to, *str):
    to = to.replace("<","")
    to = to.replace(">","")
    time_start = timer()
    time_end = None
    try:
      query = g_ldap_query.replace("%rcpt%",to)
      query = query.replace("%from%", self.F)
      self.ldap_conn.search(g_ldap_base, query)
      time_end = timer()
      if len(self.ldap_conn.entries) == 0:
        self.R.append({
          "rcpt": to, "reason": g_milter_reject_message,
          "time_start":time_start, "time_end":time_end
        })
        self.setreply('550','5.7.1',g_milter_reject_message)
        return Milter.REJECT
    except LDAPOperationResult as e:
      self.log("LDAP Exception (envrcpt): " + str(e))
      self.setreply('451','4.7.1', str(e))
      return Milter.TEMPFAIL
    self.R.append({
      "rcpt": to, "reason":'pass',"time_start":time_start,"time_end":time_end
    })
    return Milter.CONTINUE

  def data(self):
    # This callback is used only to log with queue-id
    try:
      for rcpt in self.R:
        duration = rcpt['time_end'] - rcpt['time_start']
        self.log(self.getsymval('i') +
          ": 5321.from=<" + self.F + "> 5321.rcpt=<" +
          rcpt['rcpt'] + "> reason: " + rcpt['reason'] +
          " duration: " + str(duration) + " sec."
        )
    except:
      self.log("Exception (data): " + str(sys.exc_info()))
      self.setreply('451','4.7.1', str(sys.exc_info()))
      return Milter.TEMPFAIL
    return Milter.CONTINUE

  def eom(self):
    # EOM will always be called - non-optional
    time_end = timer()
    duration = time_end - self.time_start
    self.log(self.getsymval('i') + " processing: " + str(duration) + " sec.")
    return Milter.CONTINUE

  def abort(self):
    # client disconnected prematurely
    return Milter.CONTINUE

  def close(self):
    # always called, even when abort is called.  Clean up
    # any external resources here.
    return Milter.CONTINUE

  def log(self,msg):
    log_queue.put(msg)

def logger_proc_loop():
  while True:
    qmsg = log_queue.get()
    if not qmsg: break
    logging.info(qmsg)

if __name__ == "__main__":
  try:
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
      logging.error("Missing ENV[LDAP_QUERY], e.g. " + g_ldap_query)
      sys.exit(1)
    g_ldap_query = os.environ['LDAP_QUERY']
    if 'MILTER_SOCKET' in os.environ:
      g_milter_socket = os.environ['MILTER_SOCKET']
    if 'MILTER_REJECT_MESSAGE' in os.environ:
      g_milter_reject_message = os.environ['MILTER_REJECT_MESSAGE']
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
    logger_proc = Process(target=logger_proc_loop)
    logger_proc.start()
    timeout = 600
    # Register to have the Milter factory create instances of your class:
    Milter.factory = LdapAclMilter
    # Tell the MTA which features we use
    flags = Milter.ADDHDRS
    Milter.set_flags(flags)
    logging.info("Startup " + g_milter_name + "@"+ g_milter_socket)
    Milter.runmilter(g_milter_name,g_milter_socket,timeout,True)
    log_queue.put(None)
    logger_proc.join()
    logging.info("Shutdown " + g_milter_name)
  except:
    logging.error("MAIN-EXCEPTION: " + str(sys.exc_info()))
