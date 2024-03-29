import re
from ldap3 import (
  Server, Connection, NONE, set_config_parameter,
  SAFE_RESTARTABLE
)
from ldap3.core.exceptions import LDAPException
from lam_exceptions import (
  LamPolicyBackendException, LamHardException, LamSoftException
)
from lam_rex import g_rex_domain
from lam_config_backend import LamConfigBackend
from lam_session import LamSession
from lam_log_backend import log_info, log_debug

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
      self.ldap_conn = Connection(
        server,
        self.config.ldap_binddn, 
        self.config.ldap_bindpw,
        auto_bind = True,
        raise_exceptions = True,
        client_strategy = SAFE_RESTARTABLE
      )
      log_info("policy: connected to LDAP-server: {}".format(self.config.ldap_server))
    except LDAPException as e:
      raise LamPolicyBackendException(
        "policy: Connection to LDAP-server failed: {}".format(str(e))
      ) from e

  def check_policy(self, session: LamSession, **kwargs):
    from_addr = kwargs['from_addr']
    rcpt_addr = kwargs['rcpt_addr']
    from_source = kwargs['from_source']
    m = g_rex_domain.match(from_addr)
    if m == None:
      raise LamHardException(
        "policy: Could not determine domain of from={}".format(from_addr)
      ) 
    from_domain = m.group(1)
    log_debug("policy: from_domain={}".format(from_domain), session)
    m = g_rex_domain.match(rcpt_addr)
    if m == None:
      raise LamHardException(
        "policy: Could not determine domain of rcpt={}".format(
          rcpt_addr
        )
      )
    rcpt_domain = m.group(1)
    log_debug("policy: rcpt_domain={}".format(rcpt_domain), session)
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
          log_debug("policy: auth_method: {}".format(auth_method), session)
        if self.config.milter_schema_wildcard_domain == True:
          # The asterisk (*) character is in term of local part
          # RFC5322 compliant and expected as a wildcard literal in this code.
          # As the asterisk character is special in LDAP context, thus it must
          # be ASCII-HEX encoded '\2a' (42 in decimal => answer to everything)
          # for proper use in LDAP queries.
          # In this case *@<domain> cannot be a real address!
          if re.match(r'^\*@.+$', from_addr, re.IGNORECASE):
            raise LamHardException(
              "policy: Literal wildcard sender (*@<domain>) is not " +
              "allowed in wildcard mode!"
            )
          if re.match(r'^\*@.+$', rcpt_addr, re.IGNORECASE):
            raise LamHardException(
              "policy: Literal wildcard recipient (*@<domain>) is not " +
              "allowed in wildcard mode!"
            )
          _, _, ldap_response, _ = self.ldap_conn.search(self.config.ldap_base,
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
          _, _, ldap_response, _ = self.ldap_conn.search(self.config.ldap_base,
            "(&" +
              auth_method +
              "(allowedSenders=" + query_from + ")" +
              "(!(deniedSenders=" + query_from + "))" +
              "(allowedRcpts=" + query_to + ")" +
              "(!(deniedRcpts=" + query_to + "))" +
            ")",
            attributes=['policyID']
          )
        if len(ldap_response) == 0:
          # Policy not found in LDAP
          raise LamHardException(
            "policy: mismatch: from_src={0} from={1} rcpt={2}".format(
              from_source, from_addr, rcpt_addr
            )
          )
        elif len(ldap_response) == 1:
          if from_source == 'from-header':
            log_info( 
              "policy: 5322.from_domain={} authorized by DKIM signature".format(
                from_domain
              ),
              session
            )
          # Policy found in LDAP, but which one?
          entry = ldap_response[0]['attributes']
          log_info( 
            "policy: match='{0}' from_src={1}".format(
              entry['PolicyID'][0], from_source
            ),
            session
          )
        elif len(ldap_response) > 1:
          # Something went wrong!? There shouldn´t be more than one entries!
          raise LamHardException(
            "policy: More than one policies found! from={0} rcpt={1} auth_method={2}".format(
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
        log_debug("policy: LDAP query: {}".format(query), session)
        _, _, ldap_response, _ = self.ldap_conn.search(self.config.ldap_base, query)
        if len(ldap_response) == 0:
          raise LamHardException(
            "policy: mismatch from_src={0} from={1} rcpt={2}".format(
              from_source, from_addr, rcpt_addr
            )
          )
        log_info("policy: match from_src={}".format(from_source), session)
    except LDAPException as e:
      raise LamSoftException("policy: LDAP exception: " + str(e)) from e
