import string
import random
from lam_logger import log_debug
from lam_policy_backend import LamConfigBackend

class LamSession():
  def __init__(self, client_addr: str, config: LamConfigBackend):
    self.client_addr = client_addr
    self.config = config
    self.reset()

  def reset(self):
    self.proto_stage = 'invalid'
    self.env_from = None
    self.null_sender = False
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
    log_debug("reset(): {}".format(self.__dict__))
    # https://stackoverflow.com/a/2257449
    self.mconn_id = self.config.milter_name + ': ' + ''.join(
      random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
    )

  def get_client_addr(self) -> str:
    return self.client_addr

  def set_proto_stage(self, stage: str):
    self.proto_stage = stage
  def get_proto_stage(self) -> str:
    return self.proto_stage
  
  def set_env_from(self, env_from: str):
    self.env_from = env_from
  def get_env_from(self) -> str:
    return self.env_from

  def set_null_sender(self, null_sender: bool):
    self.null_sender = null_sender
  def is_null_sender(self) -> bool:
    return self.null_sender

  def set_sasl_user(self, sasl_user: str):
    self.sasl_user = sasl_user
  def get_sasl_user(self) -> str:
    return self.sasl_user
    
  def set_x509_subject(self, x509_subject: str):
    self.x509_subject = x509_subject
  def get_x509_subject(self) -> str:
    return self.x509_subject

  def set_x509_issuer(self, x509_issuer: str):
    self.x509_issuer = x509_issuer
  def get_x509_issuer(self) -> str:
    return self.x509_issuer

  def set_queue_id(self, queue_id: str):
    self.queue_id = queue_id
  def get_queue_id(self) -> str:
    return self.queue_id

  def add_env_rcpt(self, rcpt: str):
    self.env_rcpts.append(rcpt)
  def get_env_rcpts(self) -> list:
    return self.env_rcpts

  def set_hdr_from(self, hdr_from: str):
    self.hdr_from = hdr_from
  def get_hdr_from(self) -> str:
    return self.hdr_from

  def set_hdr_from_domain(self, hdr_from_domain: str):
    self.hdr_from_domain = hdr_from_domain
  def get_hdr_from_domain(self) -> str:
    return self.hdr_from_domain

  def set_dkim_valid(self, dkim_valid: bool):
    self.dkim_valid = dkim_valid
  def is_dkim_valid(self) -> bool:
    return self.dkim_valid

  def set_dkim_aligned(self, dkim_aligned: bool):
    self.dkim_aligned = dkim_aligned
  def is_dkim_aligned(self) -> bool:
    return self.dkim_aligned

  def add_passed_dkim_result(self, dkim_result: str):
    self.passed_dkim_results.append(dkim_result)
  def get_passed_dkim_results(self) -> list:
    return self.passed_dkim_results

  def get_mconn_id(self) -> str:
    return self.mconn_id