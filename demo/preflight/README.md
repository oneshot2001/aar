# Read-only VAPIX preflight

Preflight performs only `GET /axis-cgi/param.cgi?action=list...` through a
mockable authenticated transport. It never uses `basicdeviceinfo.cgi`: POST to
that endpoint is known to enter a 401 Digest-auth loop on the lab Q6325-LE.
Credential access uses `cred get` without a shell and never prints the returned
secret. Exact Q6325-LE parameter keys and values are **FILL-AT-D2**.
