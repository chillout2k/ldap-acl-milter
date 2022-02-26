import re

# globaly used regex definitions
g_rex_domain = re.compile(r'^\S*@(\S+)$')
# http://emailregex.com/ -> Python
g_rex_email = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
g_rex_srs = re.compile(r"^SRS0=.+=.+=(\S+)=(\S+)\@.+$")