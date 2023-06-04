import logging
import re
import os
from typing import Optional
from lam_session import LamSession

def init_log_backend():
  log_level = logging.INFO
  if 'LOG_LEVEL' in os.environ:
    if re.match(r'^info$', os.environ['LOG_LEVEL'], re.IGNORECASE):
      log_level = logging.INFO
    elif re.match(r'^warn|warning$', os.environ['LOG_LEVEL'], re.IGNORECASE):
      log_level = logging.WARN
    elif re.match(r'^error$', os.environ['LOG_LEVEL'], re.IGNORECASE):
      log_level = logging.ERROR
    elif re.match(r'debug', os.environ['LOG_LEVEL'], re.IGNORECASE):
      log_level = logging.DEBUG
  log_format = '%(asctime)s: %(levelname)s %(message)s '
  logging.basicConfig(
    filename = None, # log to stdout
    format = log_format,
    level = log_level
  )
  logging.info("Logger initialized")

def do_log(level: str, log_message: str, session: Optional[LamSession] = None):
  log_line = ''
  if session is not None:
    if hasattr(session, 'mconn_id'):
      log_line = "{}".format(session.get_mconn_id())
  if session is not None:
    if session.get_queue_id() != 'invalid':
      log_line = "{0}/{1}".format(log_line, session.get_queue_id())
  if session is not None and session.get_proto_stage() != 'invalid':
    log_line = "{0}/{1}".format(log_line, session.get_proto_stage())
  log_line = "{0} {1}".format(log_line, log_message)
  if level == 'error':
    logging.error(log_line)
  elif level == 'warn' or level == 'warning':
    logging.warning(log_line)
  elif level == 'info':
    logging.info(log_line)
  elif level == 'debug':
    logging.debug(log_line)

def log_error(log_message: str, session: Optional[LamSession] = None):
  do_log('error', log_message, session)

def log_warning(log_message: str, session: Optional[LamSession] = None):
  do_log('warn', log_message, session)

def log_info(log_message: str, session: Optional[LamSession] = None):
  do_log('info', log_message, session)

def log_debug(log_message: str, session: Optional[LamSession] = None):
  do_log('debug', log_message, session)
