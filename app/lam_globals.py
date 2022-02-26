import sys
from lam_exceptions import (
  LamInitException, LamPolicyBackendException, LamConfigException
)
from lam_config import LamConfig
from lam_logger import init_logger
from lam_policy_backend import LamPolicyBackend

init_logger()

g_config = None
try:
  if g_config is None:
    g_config = LamConfig()
except LamConfigException as e:
  raise LamInitException(e.message) from e

# Instantiate the LDAP policy backend and
# establish a permanent connection with the LDAP server
# which will be reused on any milter connection
g_policy_backend = None
try:
  if g_policy_backend is None:
    g_policy_backend = LamPolicyBackend(g_config)
except LamPolicyBackendException as e:
  raise LamInitException(e.message) from e