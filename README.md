# ldap-acl-milter
A lightweight, fast and thread-safe python3 [milter](http://www.postfix.org/MILTER_README.html) on top of [sdgathman/pymilter](https://github.com/sdgathman/pymilter) for basic Access Control (ACL) scenarios. The milter consumes policies from LDAP based on custom queries with trivial templating support (%from% = RFC5321.from; %rcpt% = RFC5321.rcpt).

In the case, one already has a LDAP server running with the [amavis schema](https://www.ijs.si/software/amavisd/LDAP.schema.txt), the 'amavisWhitelistSender' attribute could be reused. The filtering direction (inbound or outbound) can be simply controlled by swapping the %from% and %rcpt% placeholders within the LDAP query template. Please have a look at the docker-compose.yml example.

The connection to the LDAP server is always persistent: one TCP-Session/one LDAP-bind shared among all milter-threads, which makes it more efficient due to less communication overhead. Thus, LDAP interactions with 2 msec. and less are realistic, depending on your environment like network round-trip-times or the load of your LDAP server. A very swag LDAP setup is to use a local read-only LDAP replica, which syncs over network with a couple of LDAP masters: [OpenLDAP does it for free!](https://www.openldap.org/doc/admin24/replication.html). This aproach eliminates network round trip times while reading operations as well as race conditions on a shared, centralized and (heavy) utilized LDAP server.

### Deployment paradigm
The intention of this project is to deploy the milter ALWAYS AND ONLY as an [OCI compliant](https://www.opencontainers.org)) container. In this case it´s [docker](https://www.docker.com). The main reason is that I´m not interested (and familiar with) in building distribution packages like .rpm, .deb, etc.. Furthermore I´m not realy a fan of 'wild and uncontrollable' software deployments like: get the code, compile it and finaly install the results 'somewhere' in the filesystem. In terms of software deployment docker provides wonderful possibilities, which I don´t want to miss anymore... No matter if in development, QA or production stage.

### docker-compose.yml
The following [docker-compose](https://docs.docker.com/compose/) file demonstrates how such a setup could be orchestrated on a single docker host or on a docker swarm cluster. In this context we use [postfix](http://www.postfix.org) as our milter-capable MTA and OpenLDAP as local LDAP replica.

```
version: '3'

volumes:
  lam_socket:
  openldap_spool:
  openldap_socket:

services:
  openldap:
    image: "your/favorite/openldap/image"
    restart: unless-stopped
    hostname: openldap
    volumes:
    - "./config/openldap:/etc/openldap:rw"
    - "openldap_spool:/var/openldap-data:rw"
    - "openldap_socket:/socket:rw"

  ldap-acl-milter:
    depends_on:
    - openldap
    image: "ldap-acl-milter/debian:19.02_master"
    restart: unless-stopped
    environment:
      #LDAP_SERVER: ldap://ldap-slave.example.local:389
      LDAP_SERVER: ldapi:///socket//slapd//slapd
      LDAP_BINDDN: uid=lam,ou=applications,dc=example,dc=org
      LDAP_BINDPW: TopSecret123!%&
      LDAP_BASE: ou=users,dc=example,dc=org
      # This example LDAP query is for inbound filtering
      # where the 'mail' attribute equals to the recipient
      # and the 'amavisWhitelistSender' attribute the eligible sender
      LDAP_QUERY: (&(mail=%rcpt%)(amavisWhitelistSender=%from%))
      # Default: UNIX-socket located under /socket/ldap-acl-milter
      # https://pythonhosted.org/pymilter/namespacemilter.html#a266a6e09897499d8b1ae0e20f0d2be73
      #MILTER_SOCKET: inet6:8020
      MILTER_REJECT_MESSAGE: Message rejected due to security policy
    hostname: ldap-acl-milter
    volumes:
    - "lam_socket:/socket/:rw"
    - "openldap_socket:/socket/slapd:ro"

  postfix:
    depends_on:
    - ldap-acl-milter
    image: "your/favorite/postfix/image"
    restart: unless-stopped
    hostname: postfix
    ports:
    - "25:25"
    volumes:
    - "./config/postfix:/etc/postfix:rw"
    - "lam_socket:/socket/ldap-acl-milter/:rw"
    - "openldap_socket:/socket/slapd:ro"
```
