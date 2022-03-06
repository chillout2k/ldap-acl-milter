import re
from lam_logger import log_info, log_debug
from lam_rex import g_rex_domain
from ldap3 import (
  Server, Connection, NONE, set_config_parameter
)
from ldap3.core.exceptions import LDAPException
from lam_exceptions import (
  LamPolicyBackendException, LamHardException, LamSoftException
)
from lam_config_backend import LamConfigBackend
from lam_session import LamSession

class LamPolicyBackend():
  def __init__(self, lam_config: LamConfigBackend):
    self.config = lam_config
    self.ldap_conn = None
    try:
      set_config_parameter("RESTARTABLE_SLEEPTIME", 2)
      set_config_parameter("RESTARTABLE_TRIES", 2)
      server = Server(
        host = self.config.ldap_server, 
        connect_timeout = self.config.ldap_server_connect_timeout,
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

  def check_policy(self, session: LamSession, **kwargs):
    from_addr = kwargs['from_addr']
    rcpt_addr = kwargs['rcpt_addr']
    from_source = kwargs['from_source']
    mcid = "{}/Policy".format(session.get_mconn_id())
    m = g_rex_domain.match(from_addr)
    if m == None:
      raise LamHardException(
        "Could not determine domain of from={0}".format(from_addr)
      )
    from_domain = m.group(1)
    log_debug("{0} from_domain={1}".format(mcid, from_domain))
    m = g_rex_domain.match(rcpt_addr)
    if m == None:
      raise LamHardException(
        "Could not determine domain of rcpt={0}".format(
          rcpt_addr
        )
      )
    rcpt_domain = m.group(1)
    log_debug("{0} rcpt_domain={1}".format(mcid, rcpt_domain))
    try:
      if self.config.milter_schema == True:
        # LDAP-ACL-Milter schema enabled
        auth_method = ''
        if self.config.milter_expect_auth == True:
          auth_method = "(|(allowedClientAddr={})%SASL_AUTH%%X509_AUTH%)".format(
            session.get_client_addr()
          )
          if session.get_sasl_user():
            auth_method = auth_method.replace(
              '%SASL_AUTH%',"(allowedSaslUser={})".format(
                session.get_sasl_user()
              )
            )
          else:
            auth_method = auth_method.replace('%SASL_AUTH%','')
          if session.get_x509_subject() and session.get_x509_issuer():
            auth_method = auth_method.replace('%X509_AUTH%',
              "(&"+
                "(allowedx509subject=" + session.get_x509_subject() + ")" +
                "(allowedx509issuer=" + session.get_x509_issuer() + ")" +
              ")"
            )
          else:
            auth_method = auth_method.replace('%X509_AUTH%','')
          log_debug("{0} auth_method: {1}".format(mcid, auth_method))
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
              "(|" +
                "(allowedSenders=" + from_addr + ")" +
                "(allowedSenders=\\2a@" + from_domain + ")" +
                "(allowedSenders=\\2a@\\2a)" +
              ")" +
              "(&" +
                "(!(deniedSenders=" + from_addr + "))" +
                "(!(deniedSenders=\\2a@" + from_domain + "))" +
                "(!(deniedSenders=\\2a@\\2a))" +
              ")" +
              "(|" +
                "(allowedRcpts=" + rcpt_addr + ")" +
                "(allowedRcpts=\\2a@" + rcpt_domain + ")" +
                "(allowedRcpts=\\2a@\\2a)" +
              ")" +
              "(&" +
                "(!(deniedRcpts=" + rcpt_addr + "))" +
                "(!(deniedRcpts=\\2a@" + rcpt_domain + "))" +
                "(!(deniedRcpts=\\2a@\\2a))" +
              ")" +
            ")",
            attributes=['policyID']
          )
        else:
          # Wildcard-domain DISABLED
          # Asterisk (*) must be ASCII-HEX encoded for LDAP queries
          query_from = from_addr.replace("*","\\2a")
          query_to = rcpt_addr.replace("*","\\2a")
          self.ldap_conn.search(self.config.ldap_base,
            "(&" +
              auth_method +
              "(allowedSenders=" + query_from + ")" +
              "(!(deniedSenders=" + query_from + "))" +
              "(allowedRcpts=" + query_to + ")" +
              "(!(deniedRcpts=" + query_to + "))" +
            ")",
            attributes=['policyID']
          )
        if len(self.ldap_conn.entries) == 0:
          # Policy not found in LDAP
          raise LamHardException(
            "mismatch: from_src={0} from={1} rcpt={2}".format(
              from_source, from_addr, rcpt_addr
            )
          )
        elif len(self.ldap_conn.entries) == 1:
          if from_source == 'from-header':
            log_info("{0} 5322.from_domain={1} authorized by DKIM signature".format(
              mcid, from_domain
            ))
          # Policy found in LDAP, but which one?
          entry = self.ldap_conn.entries[0]
          log_info("{0} match='{1}' from_src={2}".format(
            mcid, entry.policyID.value, from_source
          ))
        elif len(self.ldap_conn.entries) > 1:
          # Something went wrong!? There shouldn´t be more than one entries!
          raise LamHardException(
            "More than one policies found! from={0} rcpt={1} auth_method={2}".format(
              from_addr, rcpt_addr, auth_method
            )
          )
      else:
        # Custom LDAP schema
        # replace all placeholders in query template
        query = self.config.ldap_query.replace("%rcpt%", rcpt_addr)
        query = query.replace("%from%", from_addr)
        if self.config.milter_expect_auth:
          query = query.replace("%client_addr%", session.get_client_addr())
          if session.get_sasl_user() is not None:
            query = query.replace("%sasl_user%", session.get_sasl_user())
        query = query.replace("%from_domain%", from_domain)
        query = query.replace("%rcpt_domain%", rcpt_domain)
        log_debug("{0} LDAP query: {1}".format(mcid, query))
        self.ldap_conn.search(self.config.ldap_base, query)
        if len(self.ldap_conn.entries) == 0:
          raise LamHardException(
            "mismatch from_src={0} from={1} rcpt={2}".format(
              from_source, from_addr, rcpt_addr
            )
          )
        log_info("{0} match from_src={1}".format(mcid, from_source))
    except LDAPException as e:
      raise LamSoftException("LDAP exception: " + str(e)) from e
