#!/usr/bin/env bash
# Populate LDAP with canonical init.ldif at runtime. Tolerant to "Already exists (68)" errors.
set -euo pipefail

LDAP_HOST=${LDAP_HOST:-ldap}
LDAP_PORT=${LDAP_PORT:-389}
LDAP_ADMIN_DN=${LDAP_ADMIN_DN:-"cn=admin,dc=example,dc=org"}
LDAP_ADMIN_PASSWORD=${LDAP_ADMIN_PASSWORD:-admin}
LDIF_PATH=${LDIF_PATH:-/tmp/init.ldif}

echo "Preparing runtime LDAP population"

if [ ! -f "${LDIF_PATH}" ]; then
  echo "Copying project init.ldif to container temp file"
  cp "$(dirname "$0")/../ldap/init.ldif" "${LDIF_PATH}"
fi

try_add() {
  local file="$1"
  # Try ldapi first (if running inside container) then ldap add via admin creds
  echo "Attempting ldapadd (ldapi:/// then ldap://) for ${file}"
  set +e
  ldapadd -x -H ldapi:/// -f "${file}" >/tmp/ldapadd.out 2>&1 || true
  cat /tmp/ldapadd.out || true
  if grep -q "Already exists" /tmp/ldapadd.out || grep -q "ldap_add: Already exists" /tmp/ldapadd.out; then
    echo "ldapi ldapadd: already exists — treating as success"
    return 0
  fi

  ldapadd -x -H ldap://${LDAP_HOST}:${LDAP_PORT} -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PASSWORD}" -f "${file}" >/tmp/ldapadd.out 2>&1 || true
  cat /tmp/ldapadd.out || true
  if grep -q "Already exists" /tmp/ldapadd.out || grep -q "ldap_add: Already exists" /tmp/ldapadd.out; then
    echo "ldapadd: already exists — treating as success"
    return 0
  fi

  if [ -s /tmp/ldapadd.out ]; then
    echo "ldapadd failed (see /tmp/ldapadd.out)" >&2
    return 2
  fi
  return 0
}

for f in "${LDIF_PATH}"; do
  echo "Processing ${f}"
  n=0
  until try_add "${f}"; do
    n=$((n+1))
    if [ $n -gt 6 ]; then
      echo "Failed to add ${f} after $n attempts" >&2
      exit 1
    fi
    echo "Retrying in 2s... ($n)"
    sleep 2
  done
done

echo "LDAP population script completed"
#!/usr/bin/env bash
set -eu

LDIF_PATH="backend/ldap/bootstrap/ldif/50-bootstrap.ldif"
LDAP_HOST=${LDAP_HOST:-localhost}
LDAP_PORT=${LDAP_PORT:-389}
ADMIN_DN=${ADMIN_DN:-cn=admin,dc=example,dc=org}
ADMIN_PASS=${ADMIN_PASS:-admin}

echo "Copying LDIF into ldap container..."
docker compose exec -T ldap sh -c 'cat > /tmp/50-bootstrap.ldif' < "$LDIF_PATH"
echo "Running ldapadd inside ldap container..."

# copy LDIF into container
echo "Copying LDIF into ldap container..."
docker compose exec -T ldap sh -c 'cat > /tmp/50-bootstrap.ldif' < "$LDIF_PATH"

# run ldapadd inside the container, retry until slapd accepts binds
echo "Running ldapadd inside ldap container (will retry until slapd is ready)..."
for i in {1..20}; do
  set +e
  docker compose exec -T ldap ldapadd -c -x -D "$ADMIN_DN" -w "$ADMIN_PASS" -H ldap://localhost -f /tmp/50-bootstrap.ldif > /tmp/ldapadd.out 2>&1
  RC=$?
  set -e
  if [ $RC -eq 0 ]; then
    echo "ldapadd succeeded"
    break
  fi
  # If the only error is 'Already exists (68)' we can treat it as success (entries are present)
  if grep -q "Already exists (68)" /tmp/ldapadd.out 2>/dev/null; then
    echo "ldapadd reported 'Already exists' — entries likely present; treating as success"
    RC=0
    break
  fi
  echo "ldapadd attempt $i failed; output:" >&2
  cat /tmp/ldapadd.out >&2 || true
  sleep 2
done
if [ $RC -ne 0 ]; then
  echo "ldapadd failed after retries" >&2
  docker compose logs --no-color --tail=200 ldap | sed -n '1,200p'
  exit $RC
fi

echo "LDAP population finished. Verifying admins group..."
docker compose exec -T ldap ldapsearch -x -H ldap://localhost -D "$ADMIN_DN" -w "$ADMIN_PASS" -b "ou=groups,dc=example,dc=org" "(objectClass=*)" cn member || true

echo "Done"
