#!/usr/bin/env sh
# One-shot LDAP init script used by docker-compose (mounted into the ldap-init container).
set -eu
echo "ldap-init script starting: $(date)"
echo "Waiting for ldap to be ready (up to 60s)"
i=0
while [ $i -lt 60 ]; do
  if ldapsearch -x -H ldap://ldap:389 -b 'dc=example,dc=org' -D 'cn=admin,dc=example,dc=org' -w admin '(objectclass=*)' -LLL >/dev/null 2>&1; then
    echo "ldap is responsive (attempt $i)"
    break
  fi
  echo "ldap not ready yet (attempt $i)";
  i=$((i+1))
  sleep 1
done

if [ $i -ge 60 ]; then
  echo "ldap did not become ready in time" >&2
fi

echo "Applying /init.ldif"
ldapadd -c -x -H ldap://ldap:389 -D 'cn=admin,dc=example,dc=org' -w admin -f /init.ldif || true
echo "ldap-init script finished: $(date)"
