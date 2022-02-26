import Milter
import sys
import traceback
from lam_exceptions import LamInitException
from lam_logger import log_info, log_error
try:
  import lam_globals
except LamInitException as e:
  log_error("Init exception: {}".format(e.message))
  sys.exit(1)
from lam import LdapAclMilter

if __name__ == "__main__":  
  try:
    timeout = 600
    # Register to have the Milter factory create instances of your class:
    Milter.factory = LdapAclMilter
    # Tell the MTA which features we use
    flags = Milter.ADDHDRS
    Milter.set_flags(flags)
    log_info("Starting {0}@socket: {1} in mode {2}".format(
      lam_globals.g_config.milter_name, 
      lam_globals.g_config.milter_socket, 
      lam_globals.g_config.milter_mode
    ))
    Milter.runmilter(
      lam_globals.g_config.milter_name, 
      lam_globals.g_config.milter_socket, 
      timeout,
      True
    )
    log_info("Shutdown {}".format(lam_globals.g_config.milter_name))
  except:
    log_error("MAIN-EXCEPTION: {}".format(traceback.format_exc()))
    sys.exit(1)
