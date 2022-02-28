import Milter
import traceback
import string
import random
import re
import email.utils
import authres
from lam_backends import g_config_backend, g_policy_backend
from lam_rex import g_rex_domain, g_rex_srs
from lam_logger import log_debug, log_info, log_warning, log_error
from lam_exceptions import LamSoftException, LamHardException

class LdapAclMilter(Milter.Base):
  # Each new connection is handled in an own thread
  def __init__(self):
    # client_addr gets overriden on any connect()
    self.client_addr = None

  def do_log(self, **kwargs):
    log_line = ''
    if hasattr(self, 'mconn_id'):
      log_line = "{}".format(self.mconn_id)
    if self.queue_id != 'invalid':
      log_line = "{0}/{1}".format(log_line, self.queue_id)
    if self.proto_stage != 'invalid':
      log_line = "{0}/{1}".format(log_line, self.proto_stage)
    log_line = "{0} {1}".format(log_line, kwargs['log_message'])
    if kwargs['level'] == 'error':
      log_error(log_line)
    elif kwargs['level'] == 'warn' or kwargs['level'] == 'warning':
      log_warning(log_line)
    elif kwargs['level'] == 'info':
      log_info(log_line)
    elif kwargs['level'] == 'debug':
      log_debug(log_line)
  def log_error(self, log_message):
    self.do_log(level='error', log_message=log_message)
  def log_warn(self, log_message):
    self.do_log(level='warn', log_message=log_message)
  def log_info(self, log_message):
    self.do_log(level='info', log_message=log_message)
  def log_debug(self, log_message):
    self.do_log(level='debug', log_message=log_message)

  def reset(self):
    self.proto_stage = 'invalid'
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
    self.log_debug("reset(): {}".format(self.__dict__))
    # https://stackoverflow.com/a/2257449
    self.mconn_id = g_config_backend.milter_name + ': ' + ''.join(
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
      message = g_config_backend.milter_reject_message
      smtp_code = '550'
      smtp_ecode = '5.7.1'
      smfir = Milter.REJECT
    elif kwargs['action'] == 'tmpfail':
      message = g_config_backend.milter_tmpfail_message
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
      self.log_info("{0} - milter_action={1} message={2}".format(
        self.mconn_id, kwargs['action'], message
      ))
      self.setreply(smtp_code, smtp_ecode, message)
    return smfir

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
    self.log_debug("client_addr={0}, client_port={1}".format(
      self.client_addr, hostaddr[1])
    )
    return self.milter_action(action = 'continue')

  def envfrom(self, mailfrom, *str):
    self.reset()
    self.proto_stage = 'FROM'
    if g_config_backend.milter_expect_auth:
      try:
        # this may fail, if no x509 client certificate was used.
        # postfix only passes this macro to milters if the TLS connection
        # with the authenticating client was trusted in a x509 manner!
        # Unfortunately, postfix only passes the CN-field of the subject/issuer DN :-/
        x509_subject = self.getsymval('{cert_subject}')
        if x509_subject != None:
          self.x509_subject = x509_subject
          self.log_debug("x509_subject={}".format(self.x509_subject))
        else:
          self.log_debug("No x509_subject registered")
        x509_issuer = self.getsymval('{cert_issuer}')
        if x509_issuer != None:
          self.x509_issuer = x509_issuer
          self.log_debug("x509_issuer={}".format(self.x509_issuer))
        else:
          self.log_debug("No x509_issuer registered")
      except:
        self.log_error("x509 exception: {}".format(traceback.format_exc()))
      try:
        # this may fail, if no SASL authentication preceded
        sasl_user = self.getsymval('{auth_authen}')
        if sasl_user != None:
          self.sasl_user = sasl_user
          self.log_debug("sasl_user={}".format(self.sasl_user))
        else:
          self.log_debug("No sasl_user registered")
      except:
        self.log_error("sasl_user exception: {}".format(traceback.format_exc()))
      self.log_info(
        "auth: client_ip={0} x509_subject={1} x509_issuer={2} sasl_user={3}".format(
          self.client_addr, self.x509_subject, self.x509_issuer, self.sasl_user
        )
      )
    mailfrom = mailfrom.replace("<","")
    mailfrom = mailfrom.replace(">","")
    # BATV (https://tools.ietf.org/html/draft-levine-smtp-batv-01)
    # Strip out Simple Private Signature (PRVS)
    mailfrom = re.sub(r"^prvs=.{10}=", '', mailfrom)
    # SRS (https://www.libsrs2.org/srs/srs.pdf)
    m_srs = g_rex_srs.match(mailfrom)
    if m_srs != None:
      self.log_info("Found SRS-encoded envelope-sender: {}".format(mailfrom))
      mailfrom = m_srs.group(2) + '@' + m_srs.group(1)
      self.log_info("SRS envelope-sender replaced with: {}".format(mailfrom))
    self.env_from = mailfrom.lower()
    self.log_debug("5321.from={}".format(self.env_from))
    m = g_rex_domain.match(self.env_from)
    if m == None:
      return self.milter_action(
        action = 'reject',
        reason = "Could not determine domain of 5321.from={}".format(self.env_from)
      )
    return self.milter_action(action = 'continue')

  def envrcpt(self, to, *str):
    self.proto_stage = 'RCPT'
    to = to.replace("<","")
    to = to.replace(">","")
    to = to.lower()
    self.log_debug("5321.rcpt={}".format(to))
    if to in g_config_backend.milter_whitelisted_rcpts:
      return self.milter_action(action = 'continue')
    if g_config_backend.milter_dkim_enabled:
      # Collect all envelope-recipients for later
      # investigation (EOM). Do not perform any 
      # policy action at this protocol phase.
      self.env_rcpts.append(to)
    else:
      # DKIM disabled. Policy enforcement takes place here.
      try:
        g_policy_backend.check_policy(
          from_addr = self.env_from, 
          rcpt_addr = to, 
          from_source = 'envelope', 
          lam_session = self
        )
        self.env_rcpts.append(to)
      except LamSoftException as e:
        if g_config_backend.milter_mode == 'reject':
          return self.milter_action(action = 'tmpfail')
      except LamHardException as e:
        if g_config_backend.milter_mode == 'reject':
          return self.milter_action(
            action = 'reject',
            reason = e.message
          )
        else:
          self.log_info("TEST-Mode: {}".format(e.message))
    return self.milter_action(action = 'continue')

  def header(self, hname, hval):
    self.proto_stage = 'HDR'
    self.queue_id = self.getsymval('i')
    if g_config_backend.milter_dkim_enabled == True:
      # Parse RFC-5322-From header
      if(hname.lower() == "From".lower()):
        hdr_5322_from = email.utils.parseaddr(hval)
        self.hdr_from = hdr_5322_from[1].lower()
        m = re.match(g_rex_domain, self.hdr_from)
        if m is None:
          return self.milter_action(
            action = 'reject',
            reason = "Could not determine domain-part of 5322.from=" + self.hdr_from
          )
        self.hdr_from_domain = m.group(1)
        self.log_debug("5322.from={0}, 5322.from_domain={1}".format(
          self.hdr_from, self.hdr_from_domain
        ))
      # Parse RFC-7601 Authentication-Results header
      elif(hname.lower() == "Authentication-Results".lower()):
        ar = None
        try:
          ar = authres.AuthenticationResultsHeader.parse(
            "{0}: {1}".format(hname, hval)
          )
          if ar.authserv_id.lower() == g_config_backend.milter_trusted_authservid.lower():
            for ar_result in ar.results:
              if ar_result.method.lower() == 'dkim':
                if ar_result.result.lower() == 'pass':
                  self.passed_dkim_results.append(ar_result.header_d.lower())
                  self.log_debug("dkim=pass sdid={}".format(ar_result.header_d))
                  self.dkim_valid = True
          else:
            self.log_debug("Ignoring authentication results of {}".format(
              ar.authserv_id)
            )
        except Exception as e:
          self.log_info("AR-parse exception: {0}".format(str(e)))
    return self.milter_action(action = 'continue')

  def eom(self):
    self.proto_stage = 'EOM'
    if g_config_backend.milter_max_rcpt_enabled:
      if len(self.env_rcpts) > int(g_config_backend.milter_max_rcpt):
        if g_config_backend.milter_mode == 'reject':
          return self.milter_action(action='reject', reason='Too many recipients!')
        else:
          self.do_log("TEST-Mode: Too many recipients!")
    if g_config_backend.milter_dkim_enabled:
      self.log_info("5321.from={0} 5322.from={1} 5322.from_domain={2} 5321.rcpt={3}".format(
        self.env_from, self.hdr_from, self.hdr_from_domain, self.env_rcpts
      ))
      if self.dkim_valid:
        # There is at least one valid DKIM signature!
        # Check if one of them is also aligned
        for passed_dkim_sdid in self.passed_dkim_results:
          if self.hdr_from_domain.lower() == passed_dkim_sdid.lower():
            self.dkim_aligned = True
            self.log_info("Found aligned DKIM signature for SDID: {0}".format(
              passed_dkim_sdid
            ))
      reject_message = False
      for rcpt in self.env_rcpts:
        try:
          # Check 5321.from against policy
          g_policy_backend.check_policy(
            from_addr=self.env_from, 
            rcpt_addr=rcpt, 
            from_source='envelope', 
            lam_session=self
          )
          self.log_info(
            "action=pass 5321.from={0} 5321.rcpt={1}".format(self.env_from, rcpt)
          )
        except LamSoftException as e:
          self.log_info(e.message)
          if g_config_backend.milter_mode == 'reject':
            return self.milter_action(action = 'tmpfail')
          else:
            self.log_info("TEST-Mode - tmpfail")
        except LamHardException as e:
          self.log_info(e.message)
          if self.dkim_aligned:
            try:
              # Check 5322.from against policy
              g_policy_backend.check_policy(
                from_addr=self.hdr_from, 
                rcpt_addr=rcpt, 
                from_source='from-header', 
                lam_session=self
              )
              self.log_info(
                "action=pass 5322.from={0} 5321.rcpt={1}".format(self.hdr_from, rcpt)
              )
            except LamHardException as e:
              reject_message = True
          else:
            reject_message = True
      if reject_message:
        if g_config_backend.milter_mode == 'reject':
          return self.milter_action(
            action = 'reject',
            reason = 'policy mismatch! Message rejected for all recipients!'
          )
        else:
          self.log_info(
            "TEST-Mode: policy mismatch! Message would be rejected for all recipients!"
          )
    else:
      # * DKIM check disabled
      # Iterate through all accepted envelope recipients and log
      for rcpt in self.env_rcpts:
        self.log_info("action=pass 5321.from={0} 5321.rcpt={1}".format(self.env_from, rcpt))

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
