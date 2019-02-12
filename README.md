# ldap-acl-milter
A fast and lightweight python3 milter (on top of [sdgathman/pymilter](https://github.com/sdgathman/pymilter)) for Access ControL (ACL) scenarios. The milter consumes policies from a LDAP server based on custom queries with trivial templating (%from% = RFC5321.from; %rcpt% = RFC5321.rcpt) support.

The connection to the LDAP server is always persistent: one TCP-Session, one LDAP-bind -> less overhead

### docker-compose.yml

```
version: '3'

volumes:
  lam_socket:

services:
  ldap-acl-milter:
    image: "ldap-acl-milter/debian:19.02_devel"
    restart: unless-stopped
    environment:
      LDAP_SERVER: ldap://ldap-slave.example.org:389
      LDAP_BINDDN: uid=lam,ou=apps,dc=example,dc=org
      LDAP_BINDPW: TopSecret1!
      LDAP_BASE: ou=users,dc=example,dc=org
      LDAP_QUERY: (&(mail=%rcpt%)(whitelistSender=%from%))
      # Socket default: /socket/ldap-acl-milter
      # MILTER_SOCKET: inet6:8020
      MILTER_REJECT_MESSAGE: Rejected due to security policy violation
    hostname: ldap-acl-milter
    volumes:
    - "lam_socket:/socket/:rw"
  postfix:
    depends_on:
    - ldap-acl-milter
    image: "postfix/alpine/amd64"
    restart: unless-stopped
    hostname: postfix
    ports:
    - "25:25"
    volumes:
    - "./config/postfix:/etc/postfix:rw"
    - "lam_socket:/socket/:rw"
```
