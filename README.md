# ldap-acl-milter
A fast and lightweight and thread-safe python3 milter on top of [sdgathman/pymilter](https://github.com/sdgathman/pymilter) for Access ControL (ACL) scenarios. The milter consumes policies from a LDAP server based on custom queries with trivial templating support (%from% = RFC5321.from; %rcpt% = RFC5321.rcpt). Please have a look at the docker-compose.yml example.

So, if you already have a LDAP server running with e.g. amavis-schema, you may reuse the 'amavisWhitelistSender'/'amavisBlacklistSender' attributes. Please have a look at the docker-compose.yml example.

The connection to the LDAP server is always persistent: one TCP-Session, one LDAP-bind -> less overhead

The intention of this project is to deploy the milter ALWAYS AND ONLY as a docker container. The main reason ist that I´m not so familiar with/interested in building distribution packages (rpm, deb, ...). Furthermore I´m not realy a fan of 'wild and uncontrollable' software deployments: get the code, compile and finaly install the results 'somewhere' in the filesystem. In term of CI/CD docker gives us wonderful possibilities I don´t want to miss anymore...

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
      LDAP_QUERY: (&(mail=%rcpt%)(amavisWhitelistSender=%from%))
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
