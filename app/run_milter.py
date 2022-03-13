import Milter
import sys
import traceback
from lam_exceptions import LamInitException
from lam_log_backend import log_info, log_error
try:
  import lam_backends
except LamInitException as e:
  log_error("Init exception: {}".format(e.message))
  sys.exit(1)
from lam import LdapAclMilter

if __name__ == "__main__":  
  try:
    # Register to have the Milter factory create instances of your class:
    Milter.factory = LdapAclMilter
    # Tell the MTA which features we use
    flags = Milter.ADDHDRS
    Milter.set_flags(flags)
    log_info("Starting {}".format(
      lam_backends.g_config_backend.milter_name
    ))
    Milter.runmilter(
      lam_backends.g_config_backend.milter_name, 
      lam_backends.g_config_backend.milter_socket, 
      lam_backends.g_config_backend.milter_timeout,
      True
    )
    log_info("Shutdown {}".format(lam_backends.g_config_backend.milter_name))
  except:
    log_error("MAIN-EXCEPTION: {}".format(traceback.format_exc()))
    sys.exit(1)
