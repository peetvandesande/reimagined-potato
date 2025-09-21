This folder contains the canonical LDAP bootstrap data used by the development environment.

Strategy chosen for reliability
 - We use the upstream osixia/openldap image for the ldap service and apply the canonical
   `init.ldif` at runtime using a one-shot container (`ldap-init`) that runs during
   `docker compose up`.
 - This approach is idempotent and avoids image-level bootstrap fragility (status 68 errors)
   that can happen when host mounts or previous partial bootstraps exist.

Files
 - `init.ldif` - the canonical LDIF used to populate the directory (users and groups).
 - `../scripts/ldap_init_compose.sh` - the helper script mounted into the `ldap-init`
    container; it waits for LDAP to be responsive and then runs `ldapadd -c` to apply
    `/init.ldif`.
 - `../scripts/ldap_populate.sh` - a manual helper you can run on the host when needed.

How it runs automatically
 - `docker compose up` will start `ldap` and then the `ldap-init` one-shot service.
 - `ldap-init` waits for LDAP to be reachable, applies `/init.ldif` idempotently, and exits.

Manual population (if you need to reapply later)
 - Run the included helper (from the repo root):

```bash
./backend/scripts/ldap_populate.sh LDIF_PATH=backend/ldap/init.ldif
```

Verification
 - To check the admins group after startup:

```bash
docker compose exec ldap ldapsearch -x -H ldap://localhost:389 -D 'cn=admin,dc=example,dc=org' -w admin -b 'ou=groups,dc=example,dc=org' '(cn=admins)' -LLL
```

If you prefer a baked-in image bootstrap in the future I can try to re-enable it, but
runtime population is a reliable default for local development.

Cleanup
 - Removed legacy `empty_ldif/` and duplicate debug files to keep this folder tidy.
 - If you see an empty or leftover bootstrap folder (for example from older attempts),
   it's safe to remove it. To re-run population after cleanup, use either the one-shot
   compose init or the manual helper:

```bash
docker compose up --no-deps --abort-on-container-exit ldap-init
# or
./backend/scripts/ldap_populate.sh LDIF_PATH=backend/ldap/init.ldif
```
