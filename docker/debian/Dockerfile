ARG http_proxy
ARG https_proxy
FROM debian
LABEL maintainer="Dominik Chilla <dominik@zwackl.de>"
LABEL git_repo="https://github.com/chillout2k/ldap-acl-milter"

ENV DEBIAN_FRONTEND=noninteractive \
 TZ=Europe/Berlin

RUN env; set -ex ; \
    apt-get -qq update \
 && apt-get -qq --no-install-recommends install \
     python3-pip python3-setuptools python3-ldap3 \
     libmilter1.0.1 libmilter-dev procps net-tools \
     gcc python3-dev \
 && /usr/bin/pip3 install pymilter \
 && /bin/mkdir /config /socket /app \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

ADD app/*.py /app/
ADD entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/bin/python3", "/app/ldap-acl-milter.py"]
