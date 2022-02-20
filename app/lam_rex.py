import re

rex_domain = re.compile(r'^\S*@(\S+)$')
# http://emailregex.com/ -> Python
rex_email = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
rex_srs = re.compile(r"^SRS0=.+=.+=(\S+)=(\S+)\@.+$")