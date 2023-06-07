import Milter
import traceback
import re
import email.utils
import authres
from lam_backends import g_config_backend, g_policy_backend
from lam_rex import g_rex_domain, g_rex_srs
from lam_log_backend import log_debug, log_info, log_warning, log_error
from lam_exceptions import LamSoftException, LamHardException
from lam_session import LamSession

class LdapAclMilter(Milter.Base):
  # Each new connection is handled in an own thread
  def __init__(self):
    self.session = None

  def milter_action(self, **kwargs) -> int:
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
    if self.session.get_queue_id() != 'invalid':
      message = " queue_id: {0} - {1}".format(self.session.get_queue_id(), message)
    # append reason to message
    if 'reason' in kwargs:
      message = "{0} - reason: {1}".format(message, kwargs['reason'])
    if kwargs['action'] == 'reject' or kwargs['action'] == 'tmpfail':
      log_info(
        "milter_action={0} message={1}".format(kwargs['action'], message),
        self.session
      )
      self.setreply(smtp_code, smtp_ecode, message)
    return smfir

  def connect(self, IPname, family, hostaddr):
    self.session = LamSession(hostaddr[0])
    self.session.set_proto_stage('CONNECT')
    return self.milter_action(action = 'continue')

  def envfrom(self, mailfrom, *str):
    self.session.reset()
    self.session.set_proto_stage('FROM')
    if g_config_backend.milter_expect_auth:
      try:
        # this may fail, if no x509 client certificate was used.
        # postfix only passes this macro to milters if the TLS connection
        # with the authenticating client was trusted in a x509 manner (CA trust)!
        # Unfortunately, postfix only passes the CN-field of the subject/issuer DN :-/
        x509_subject = self.getsymval('{cert_subject}')
        if x509_subject != None:
          self.session.set_x509_subject(x509_subject)
        log_debug(
          "x509_subject={}".format(self.session.get_x509_subject()),
          self.session
        )
        x509_issuer = self.getsymval('{cert_issuer}')
        if x509_issuer != None:
          self.session.set_x509_issuer(x509_issuer)
        log_debug(
          "x509_issuer={}".format(self.session.get_x509_issuer()),
          self.session
        )
      except:
        log_error(
          "x509 exception: {}".format(traceback.format_exc()),
          self.session
        )
      try:
        # this may fail, if no SASL authentication preceded
        sasl_user = self.getsymval('{auth_authen}')
        if sasl_user != None:
          self.session.set_sasl_user(sasl_user)
        log_debug(
          "sasl_user={}".format(self.session.get_sasl_user()),
          self.session
        )
      except:
        log_error(
          "sasl_user exception: {}".format(traceback.format_exc()),
          self.session
        )
      log_info(
        "auth: client_ip={0} sasl_user={1} x509_subject={2} x509_issuer={3}".format(
          self.session.get_client_addr(), self.session.get_sasl_user(),
          self.session.get_x509_subject(), self.session.get_x509_issuer()
        ),
        self.session
      )
    if mailfrom == '<>':
      self.session.set_null_sender(True)
    if g_config_backend.milter_allow_null_sender and self.session.is_null_sender():
      log_info("Null-sender accepted - skipping policy checks", self.session)
    else:
      mailfrom = mailfrom.replace("<","")
      mailfrom = mailfrom.replace(">","")
      # BATV (https://tools.ietf.org/html/draft-levine-smtp-batv-01)
      # Strip out Simple Private Signature (PRVS)
      mailfrom = re.sub(r"^prvs=.{10}=", '', mailfrom)
      # SRS (https://www.libsrs2.org/srs/srs.pdf)
      m_srs = g_rex_srs.match(mailfrom)
      if m_srs != None:
        log_info(
          "Found SRS-encoded envelope-sender: {}".format(mailfrom),
          self.session
        )
        mailfrom = m_srs.group(2) + '@' + m_srs.group(1)
        log_info(
          "SRS envelope-sender replaced with: {}".format(mailfrom),
          self.session
        )
      self.session.set_env_from(mailfrom.lower())
      log_debug("5321.from={}".format(self.session.get_env_from()), self.session)
      m = g_rex_domain.match(self.session.get_env_from())
      if m == None:
        return self.milter_action(
          action = 'reject',
          reason = "Could not determine domain of 5321.from={}".format(
            self.session.get_env_from()
          )
        )
    return self.milter_action(action = 'continue')

  def envrcpt(self, to, *str):
    self.session.set_proto_stage('RCPT')
    if g_config_backend.milter_allow_null_sender and self.session.is_null_sender():
      return self.milter_action(action = 'continue')
    to = to.replace("<","")
    to = to.replace(">","")
    to = to.lower()
    log_debug("5321.rcpt={}".format(to), self.session)
    if to in g_config_backend.milter_whitelisted_rcpts:
      log_info(
        "Welcome-listed rcpt={} - skipping policy checks".format(to),
        self.session
      )
      return self.milter_action(action = 'continue')
    if g_config_backend.milter_dkim_enabled:
      # Collect all envelope-recipients for later
      # investigation (EOM). Do not perform any 
      # policy action in this protocol stage.
      self.session.add_env_rcpt(to)
    else:
      # DKIM disabled. Policy enforcement takes place here.
      try:
        g_policy_backend.check_policy(
          self.session,
          from_addr = self.session.get_env_from(), 
          rcpt_addr = to, 
          from_source = 'envelope'
        )
        self.session.add_env_rcpt(to)
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
          log_info("TEST-Mode: {}".format(e.message), self.session)
    return self.milter_action(action = 'continue')
  
  def data(self):
    self.session.set_proto_stage('DATA')
    self.session.set_queue_id(self.getsymval('i'))
    log_debug(
      "Queue-id: {}".format(self.session.get_queue_id()),
      self.session
    )
    return self.milter_action(action = 'continue')

  def header(self, hname, hval):
    self.session.set_proto_stage('HDR')
    if g_config_backend.milter_allow_null_sender and self.session.is_null_sender():
      return self.milter_action(action = 'continue')
    if g_config_backend.milter_dkim_enabled == True:
      # Parse RFC-5322-From header
      if(hname.lower() == "from"):
        log_debug("hname={0}, hval={1}".format(hname, hval), self.session)
        hdr_5322_from = email.utils.parseaddr(hval)
        self.session.set_hdr_from(hdr_5322_from[1].lower())
        m = re.match(g_rex_domain, self.session.get_hdr_from())
        if m is None:
          log_warning(
            "Could not determine domain part of 5322.from={}".format(
              self.session.get_hdr_from()
            ),
            self.session
          )
          return self.milter_action(action = 'continue')
        self.session.set_hdr_from_domain(m.group(1))
        log_debug(
          "5322.from={0}, 5322.from_domain={1}".format(
            self.session.get_hdr_from(), self.session.get_hdr_from_domain()
          ),
          self.session
        )
      # Parse RFC-7601 Authentication-Results header
      elif(hname.lower() == "authentication-results"):
        if not self.session.get_hdr_from_domain():
          log_debug("DKIM validation impossible - no 5321.from_domain", self.session)
          return self.milter_action(action = 'continue')
        log_debug("hname={0}, hval={1}".format(hname, hval), self.session)
        ar = None
        try:
          ar = authres.AuthenticationResultsHeader.parse(
            "{0}: {1}".format(hname, hval)
          )
          if ar.authserv_id.lower() == g_config_backend.milter_trusted_authservid.lower():
            for ar_result in ar.results:
              if ar_result.method.lower() == 'dkim':
                if ar_result.result.lower() == 'pass':
                  self.session.add_passed_dkim_result(ar_result.header_d.lower())
                  log_debug(
                    "dkim=pass sdid={}".format(ar_result.header_d),
                    self.session
                  )
                  self.session.set_dkim_valid(True)
          else:
            log_debug(
              "Ignoring authentication results of {}".format(ar.authserv_id),
              self.session
            )
        except Exception as e:
          log_warning("AR-parse exception: {0}".format(str(e)), self.session)
    return self.milter_action(action = 'continue')

  # Not registered/used callbacks
  @Milter.nocallback
  def eoh(self):
    return self.milter_action(action = 'continue')
  @Milter.nocallback
  def body(self, chunk):
    return self.milter_action(action = 'continue')

  def eom(self):
    self.session.set_proto_stage('EOM')
    if g_config_backend.milter_max_rcpt_enabled:
      if len(self.session.get_env_rcpts()) > int(g_config_backend.milter_max_rcpt):
        if g_config_backend.milter_mode == 'reject':
          return self.milter_action(action='reject', reason='Too many recipients!')
        else:
          log_error("TEST-Mode: Too many recipients!", self.session)
    if g_config_backend.milter_allow_null_sender and self.session.is_null_sender():
      return self.milter_action(action = 'continue')
    if g_config_backend.milter_dkim_enabled:
      log_info(
        "5321.from={0} 5322.from={1} 5322.from_domain={2} 5321.rcpt={3}".format(
          self.session.get_env_from(), self.session.get_hdr_from(), 
          self.session.get_hdr_from_domain(), self.session.get_env_rcpts()
        ),
        self.session
      )
      if self.session.is_dkim_valid():
        # There is at least one valid DKIM signature!
        # Check if one of them is also aligned
        for passed_dkim_sdid in self.session.get_passed_dkim_results():
          if self.session.get_hdr_from_domain().lower() == passed_dkim_sdid.lower():
            self.session.set_dkim_aligned(True)
            log_info(
              "Found aligned DKIM signature for SDID={0}".format(
                passed_dkim_sdid
              ),
              self.session
            )
      reject_message = False
      for rcpt in self.session.get_env_rcpts():
        if rcpt in g_config_backend.milter_whitelisted_rcpts:
          log_info("Welcome-listed rcpt={}".format(rcpt), self.session)
        try:
          # Check 5321.from <-> 5321.rcpt against policy
          g_policy_backend.check_policy(
            self.session,
            from_addr=self.session.get_env_from(), 
            rcpt_addr=rcpt, 
            from_source='envelope'
          )
          log_info(
            "action=pass 5321.from={0} 5321.rcpt={1}".format(
              self.session.get_env_from(), rcpt
            ),
            self.session
          )
        except LamSoftException as e:
          log_info(str(e), self.session)
          if g_config_backend.milter_mode == 'reject':
            return self.milter_action(action = 'tmpfail')
          else:
            log_info("TEST-Mode - tmpfail: {}".format(str(e)), self.session)
        except LamHardException as e:
          log_info(e.message, self.session)
          if self.session.is_dkim_aligned():
            try:
              # Check 5322.from <-> 5321.rcpt against policy
              g_policy_backend.check_policy(
                self.session,
                from_addr=self.session.get_hdr_from(), 
                rcpt_addr=rcpt, 
                from_source='from-header'
              )
              log_info(
                "action=pass 5322.from={0} 5321.rcpt={1}".format(
                  self.session.get_hdr_from(), rcpt
                ),
                self.session
              )
            except LamSoftException as e:
              log_info(str(e), self.session)
              if g_config_backend.milter_mode == 'reject':
                return self.milter_action(action = 'tmpfail')
              else:
                log_info("TEST-Mode - tmpfail: {}".format(str(e)), self.session)
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
          log_info(
            "TEST-Mode: policy mismatch! Message would be rejected for all recipients!",
            self.session
          )
    else:
      # * DKIM check disabled
      # Iterate through all accepted envelope recipients and log success
      for rcpt in self.session.get_env_rcpts():
        log_info(
          "action=pass 5321.from={0} 5321.rcpt={1}".format(
            self.session.get_env_from(), rcpt
          ),
          self.session
        )
    # No policy violations so far :-)
    return self.milter_action(action = 'continue')

  def abort(self):
    # Client disconnected prematurely
    self.session.set_proto_stage('ABORT')
    return self.milter_action(action = 'continue')

  def close(self):
    # Always called, even when abort is called.
    # Clean up any external resources here.
    self.session.set_proto_stage('CLOSE')
    return self.milter_action(action = 'continue')
