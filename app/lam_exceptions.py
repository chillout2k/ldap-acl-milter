class LamException(Exception):
  def __init__(self, message="General exception message"):
    self.message = message
  def __str__(self) -> str:
    return self.message

class LamInitException(LamException):
  pass

class LamSoftException(LamException):
  pass

class LamHardException(LamException):
  pass

class LamPolicyBackendException(LamException):
  pass

class LamConfigBackendException(LamException):
  pass
