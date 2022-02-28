import traceback
from lam_exceptions import (
  LamInitException, LamPolicyBackendException, LamConfigBackendException
)
from lam_logger import init_logger
from lam_config_backend import LamConfigBackend 
from lam_policy_backend import LamPolicyBackend

init_logger()

g_config_backend = None
try:
  if g_config_backend is None:
    g_config_backend = LamConfigBackend()
except LamConfigBackendException as e:
  raise LamInitException(e.message) from e
except Exception as e:
  raise LamInitException(traceback.format_exc()) from e

# Instantiate the LDAP policy backend and
# establish a permanent connection with the LDAP server
# which will be reused on any milter connection
g_policy_backend = None
try:
  if g_policy_backend is None:
    g_policy_backend = LamPolicyBackend(g_config_backend)
except LamPolicyBackendException as e:
  raise LamInitException(e.message) from e
except Exception as e:
  raise LamInitException(traceback.format_exc()) from e