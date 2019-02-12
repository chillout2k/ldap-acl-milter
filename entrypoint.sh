#!/bin/sh

set -x
set -e
umask 0000
ulimit -n 1024
/usr/bin/python3 /app/ldap-acl-milter.py
