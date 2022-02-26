import re
from lam_logger import log_info, log_debug, log_error
from lam_rex import g_rex_domain
from ldap3 import (
  Server, Connection, NONE, set_config_parameter
)
from ldap3.core.exceptions import LDAPException
from lam_exceptions import (
  LamPolicyBackendException, LamHardException, LamSoftException
)

class LamPolicyBackend():
  def __init__(self, lam_config):
    self.config = lam_config
    self.ldap_conn = None
    try:
      set_config_parameter("RESTARTABLE_SLEEPTIME", 2)
      set_config_parameter("RESTARTABLE_TRIES", 2)
      server = Server(
        self.config.ldap_server, 
        connect_timeout = 3,
        get_info = NONE
      )
      self.ldap_conn = Connection(server,
        self.config.ldap_binddn, 
        self.config.ldap_bindpw,
        auto_bind = True,
        raise_exceptions = True,
        client_strategy = 'RESTARTABLE'
      )
      log_info("Connected to LDAP-server: {}".format(self.config.ldap_server))
    except LDAPException as e:
      raise LamPolicyBackendException(
        "Connection to LDAP-server failed: {}".format(str(e))
      ) from e

  def check_policy(self, **kwargs) -> str:
    from_addr = kwargs['from_addr']
    rcpt_addr = kwargs['rcpt_addr']
    from_source = kwargs['from_source']
    lam_session = kwargs['lam_session']
    m = g_rex_domain.match(from_addr)
    if m == None:
      log_info("Could not determine domain of from={0}".format(
        from_addr
      ))
      raise LamSoftException()
    from_domain = m.group(1)
    log_debug("from_domain={}".format(from_domain))
    m = g_rex_domain.match(rcpt_addr)
    if m == None:
      raise LamHardException(
        "Could not determine domain of rcpt={0}".format(
          rcpt_addr
        )
      )
    rcpt_domain = m.group(1)
    log_debug("rcpt_domain={}".format(rcpt_domain))
    try:
      if self.config.milter_schema == True:
        # LDAP-ACL-Milter schema
        auth_method = ''
        if self.config.milter_expect_auth == True:
          auth_method = "(|(allowedClientAddr="+lam_session.client_addr+")%SASL_AUTH%%X509_AUTH%)"
          if lam_session.sasl_user:
            auth_method = auth_method.replace(
              '%SASL_AUTH%',"(allowedSaslUser="+lam_session.sasl_user+")"
            )
          else:
            auth_method = auth_method.replace('%SASL_AUTH%','')
          if lam_session.x509_subject and lam_session.x509_issuer:
            auth_method = auth_method.replace('%X509_AUTH%',
              "(&"+
                "(allowedx509subject="+lam_session.x509_subject+")"+
                "(allowedx509issuer="+lam_session.x509_issuer+")"+
              ")"
            )
          else:
            auth_method = auth_method.replace('%X509_AUTH%','')
          log_debug("auth_method: {}".format(auth_method))
        if self.config.milter_schema_wildcard_domain == True:
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
          self.ldap_conn.search(self.config.ldap_base,
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
          self.ldap_conn.search(self.config.ldap_base,
            "(&" +
              auth_method +
              "(allowedRcpts=" + query_to + ")" +
              "(allowedSenders=" + query_from + ")" +
            ")",
            attributes=['policyID']
          )
        if len(self.ldap_conn.entries) == 0:
          # Policy not found in LDAP
          ex = "policy mismatch: from={0} from_src={1} rcpt={2}".format(
            from_addr, from_source, rcpt_addr
          )
          if self.config.milter_expect_auth == True:
            ex = "policy mismatch: from={0} from_src={1} rcpt={2} auth_method={3}".format(
              from_addr, from_source, rcpt_addr, auth_method
            )
          raise LamHardException(ex)
        elif len(self.ldap_conn.entries) == 1:
          # Policy found in LDAP, but which one?
          entry = self.ldap_conn.entries[0]
          return "policy match: '{0}' from_src={1}".format(
            entry.policyID.value, from_source
          )
        elif len(self.ldap_conn.entries) > 1:
          # Something went wrong!? There shouldn´t be more than one entries!
          log_error("More than one policies found! from={0} rcpt={1} auth_method={2}".format(
            from_addr, rcpt_addr, auth_method
          ))
          raise LamHardException("More than one policies found!")
      else:
        # Custom LDAP schema
        # 'build' a LDAP query per recipient
        # replace all placeholders in query templates
        query = self.config.ldap_query.replace("%rcpt%", rcpt_addr)
        query = query.replace("%from%", from_addr)
        query = query.replace("%client_addr%", lam_session.client_addr)
        query = query.replace("%sasl_user%", lam_session.sasl_user)
        query = query.replace("%from_domain%", from_domain)
        query = query.replace("%rcpt_domain%", rcpt_domain)
        log_debug("LDAP query: {}".format(query))
        self.ldap_conn.search(self.config.ldap_base, query)
        if len(self.ldap_conn.entries) == 0:
          log_info(
            "policy mismatch from={0} from_src={1} rcpt={2}".format(
              from_addr, from_source, rcpt_addr
            )
          )
          raise LamHardException("policy mismatch")
        return "policy match: '{0}' from_src={1}".format(
          entry.policyID.value, from_source
        )
    except LDAPException as e:
      log_error("LDAP exception: {}".format(str(e)))
      raise LamSoftException("LDAP exception: " + str(e)) from e
