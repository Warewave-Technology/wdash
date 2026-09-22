# Running WDash on Kubernetes

These manifests install one WDash instance: the server, its metadata database
on a volume, the alert evaluator beside it, and a way in through your ingress
controller.

There was no page like this, and no `kustomization.yaml` either, so the install
order was whatever `kubectl apply -f kubernetes/` derived from the filenames.
It also meant nothing said which values have to change before an apply — and
the two that mattered most shipped with working defaults, which is worse than
shipping nothing.

## Before you apply

Two things, and neither starts without you.

**0. The image needs nothing from you any more.** The manifests name
`yigitbasalma/wdash-elastic-dashboard:3.1.1`, and that tag is published, for
`linux/amd64` and `linux/arm64` both. This page used to say the published
images stopped at 2.2.4 and that an apply would leave every container in
`ErrImagePull`; that was true, and it is the reason the rest of this section
exists.

You still need the steps below if your cluster pulls from a registry of its
own — an air-gapped one, or a mirror:

```bash
docker pull yigitbasalma/wdash-elastic-dashboard:3.1.1
docker tag  yigitbasalma/wdash-elastic-dashboard:3.1.1 \
            <registry>/wdash-elastic-dashboard:3.1.1
docker push <registry>/wdash-elastic-dashboard:3.1.1
cd kubernetes && kustomize edit set image \
    yigitbasalma/wdash-elastic-dashboard=<registry>/wdash-elastic-dashboard:3.1.1
```

Retag rather than rebuild: a rebuild on your machine is a different image
under the same version, and which one a node has then depends on when it
pulled. `wdash-agent.yaml` is not part of the kustomization; set its `image:`
by hand.

**1. The two secrets.** Both are empty on purpose, and they are empty for
different reasons.

`secret-key` used to ship as a working key printed in this repository, so an
unedited apply signed every session cookie — including the administrator's —
with a string anybody can read. The application now refuses to start on its
development key while `SESSION_COOKIE_SECURE` is true, so an unfilled Secret
fails with a message rather than quietly running forgeable.

`encryption-key` has no such guard, because an empty string is valid base64
and nothing can tell it from a key. **The pod starts and no local account can
sign in.** Every local account needs an authenticator now; its shared secret
is sealed with this key, and the store will not write a secret as plain text —
so enrolment fails, and enrolment is the first thing a new account does. The
application says so at start-up, as an ERROR rather than a warning:

```
WDASH_ENCRYPTION_KEY is not set, so NO LOCAL ACCOUNT CAN SIGN IN: the
authenticator every local account needs cannot be stored.
```

Only a directory sign-in works until a key is set.

```bash
kubectl create namespace wdash

kubectl -n wdash create secret generic wdash-secrets \
    --from-literal=secret-key="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')" \
    --from-literal=encryption-key="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
```

Back the encryption key up with the database and not separately from it.
Changing it later makes every stored credential undecryptable — source
passwords, the OIDC client secret, the LDAP bind password — and every
enrolled authenticator with them. A sign-in then reports that a stored
secret could not be decrypted, and `recover --reset-totp` below is the way
out, one account at a time.

`secrets.yaml` is a template and the kustomization does not apply it: an
apply would overwrite whatever you created here with empty values, and the
next restart would refuse to start on a session key it no longer had. Create
the Secret once, keep the file as the record of what goes in it.

**2. The hostname**: the `host` and `tls` entries in `ingress.yaml`. The
redirect URI typed on the OpenID Connect card after the first sign-in has to
be `https://<that host>/auth/callback`, and the same URI registered at the
provider; a mismatch surfaces as the provider refusing an unknown redirect
URI, which names neither.

Nothing in these files names a data source or a directory, and nothing needs
to. **Sources are declared on the configuration page** after the first
sign-in and stored in the metadata database: Elasticsearch, Loki,
VictoriaLogs, Jaeger, Tempo, one cluster or several, each with its own
credentials, index patterns and certificate authority. **So are OpenID
Connect and LDAP**, under Authentication, the client secret and bind password
sealed with the encryption key. An earlier version of these files declared
one Elasticsearch and an OpenID Connect provider in the ConfigMap as well,
with their credentials in the Secret; a pod that still carries those keys is
told so at start-up, as an ERROR naming them, and reads nothing from them —
so add the cluster and save the provider on the page before upgrading such
a deployment, or its logs, traces and monitors pages come up with no source
and nobody signs in through the provider until somebody does.

## Apply

```bash
kubectl apply -k kubernetes/
kubectl -n wdash rollout status deploy/wdash
```

Then open the hostname. The first visit lands on `/setup`, which claims the
installation with a local administrator account; every route redirects there
until it does. That account keeps working when the identity provider does not,
which is exactly what makes it worth protecting.

**Have a phone to hand.** Setup does not end at the account. Claiming the
installation hands straight over to `/auth/totp/enrol`, which shows a QR code
and will not let that account in until it has been scanned and a code typed
back. Every sign-in after the first asks for a code, and a code that has been
used once is refused. This is not optional and there is no way to turn it off,
so an installation set up by somebody who then loses the phone needs
`recover --reset-totp` below.

Local accounts are managed afterwards on the configuration page, under
**Authentication → Local accounts**.

**Then add a source**, under **Configuration → Sources**: the cluster's
address, its credentials, and which indices hold logs, traces and synthetic
monitors. It is in use the moment it is saved, on every replica, with no
restart. Until one is saved the logs, traces and monitors pages say they
have no source, which is the truth rather than an outage.

**And the directory**, under **Configuration → Authentication**: the OpenID
Connect card or the LDAP card, one of them in force at a time. The redirect
URI on the OpenID Connect card is `https://<the ingress host>/auth/callback`.
Both take effect on save; until one is saved, only local accounts sign in.

**Roles are made on the configuration page, not in these files.** A new
installation starts with three — `admin`, `developer` and `viewer`, mapped
from the directory groups `wdash-admins`, `wdash-developers` and
`wdash-viewers` — and **Roles & access** is where they are changed, where
others are made, and where a group or a named person is mapped onto one.
Nothing in this directory feeds them, and no restart or upgrade changes a
role that exists. An installation made from an earlier version of these files
imported its roles from an `rbac.yaml` in a second ConfigMap, and keeps what
it imported.

## When nobody can sign in

A lost phone, a rotated `encryption-key`, an account somebody switched off, a
directory nobody can reach — each of these locks the door from the inside, and
in every case the page that would fix it is behind the sign-in that is broken.
The way back is a shell on the pod, which is the right bar: whoever can read
the metadata store could do all of this with SQL anyway.

```bash
kubectl -n wdash exec -it deploy/wdash -c wdash -- sh
```

`DATABASE_URL` and `WDASH_ENCRYPTION_KEY` are already in that shell's
environment, so every command below finds the store the application runs on
without being told where it is.

```bash
# Start here. Names the store, the directory in force, the roles, who may
# administer, and which local accounts exist.
python -m wdash.store.recover --status

# A lost phone, or an encryption key that was rotated. The next sign-in
# enrols a new authenticator; until then the password alone gets in.
python -m wdash.store.recover --reset-totp <username>

# An account that was switched off.
python -m wdash.store.recover --enable <username>

# Two directories, and the one in force is the one nobody can reach. WDash
# signs people in through at most ONE — with both enabled, the card saved
# most recently — and `none` leaves local accounts.
python -m wdash.store.recover --use-directory ldap
```

`--use-directory` takes `ldap`, `oidc` or `none`. `--grant-admin`,
`--set-role` and `--reset-password` are there too, for the older shapes of the
same problem.

## What is in the pod

| Container | What it is |
| --- | --- |
| `wdash` | gunicorn, four workers, on port 5000 |
| `alerts` | `python -m wdash.alerts`, evaluating rules every 30 seconds |
| `nginx` | the sidecar on port 8080: static files, and the proxy in front |

The evaluator is a **separate process, in the same pod**. Separate because
evaluation has to run when nothing is arriving — an agent going completely
silent produces no requests at all, and that is when somebody needs telling.
Same pod because it reads the same SQLite file on the same ReadWriteOnce
volume, and a second pod would have to be scheduled onto the same node to
mount it.

Only the sidecar's port is on the Service. The application's own port is not,
because `TRUSTED_PROXY_COUNT` tells WDash to believe `X-Forwarded-For`: a
request arriving directly on 5000 could name any client address it liked and
walk through the per-address sign-in throttle with it.

The kubelet asks the `wdash` container three questions, and none of them is
`/health`:

| Probe | Path | What it asks |
| --- | --- | --- |
| startup | `/livez` | is the process up — five minutes of grace, because migrations run at start-up and a large Postgres is not instant |
| liveness | `/livez` | anything outside the process is not something a restart can fix, so it asks nothing outside it |
| readiness | `/readyz` | can the metadata store be reached — which is all that decides whether anybody can be served |

`/health` asks every configured backend in turn, inside the request. One that
hangs made it answer in twenty seconds, past every timeout here: the pod left
the Service and the kubelet restarted a container that was fine. It is for
alerting and for people, and it is the one endpoint that answers before
sign-in — which also makes it the one that reports the running version.

## Probe agents

`wdash-agent.yaml` runs a probe agent, and it is not applied by default because
it needs a token that does not exist until you create the agent.

```bash
# Configuration → Agents → Add agent, then:
kubectl -n wdash create secret generic wdash-agent \
    --from-literal=agent-token=<the token>
kubectl -n wdash apply -f kubernetes/wdash-agent.yaml
```

An agent inside the cluster measures the service from inside the cluster. One
outside measures what your users experience. They answer different questions,
and it is reasonable to run both — give each its own token, because the agents
page identifies an agent by it.

Browser journeys need the browser image, `yigitbasalma/wdash-browser:3.1.1` —
557MB against the server's 79MB on amd64, and published for the same two
architectures:

```bash
docker pull yigitbasalma/wdash-browser:3.1.1
# or, for a registry of your own, retag as above
```

Raise the agent's memory limit with it: Chromium needs gigabytes, not the
256Mi the plain agent is given. The manifest already mounts a writable `/tmp`,
which Chromium cannot start without on a read-only root filesystem. An agent
with no browser reports nothing for a journey — it says so in its own log —
so the journey reads unknown rather than down.

## More than one replica

`replicas: 1` and `strategy: Recreate` are not caution, they are the SQLite
file. One ReadWriteOnce volume cannot be mounted by a second pod on another
node, and a rolling update tries to start one before the old pod lets go — the
symptom is an upgrade stuck in `ContainerCreating` behind a healthy old pod,
which reads as a storage fault.

To scale out:

1. create an empty Postgres database, and copy what is on the volume into it
   from the pod that has the volume — accounts, roles, sources, dashboards,
   the audit trail, monitors and their history, alerting, all of it:

   ```bash
   kubectl -n wdash exec deploy/wdash -c wdash -- python -m wdash.store.copy \
       --from sqlite:////data/wdash.db \
       --to 'postgresql+psycopg://user:pass@host/wdash'
   ```

   It refuses a target that holds anything somebody wrote — the built-in
   roles migrating an empty database gives it are replaced by the volume's
   — counts both sides afterwards, and copies the sealed credentials as
   they are, so keep the same `encryption-key` in the Secret;
2. point `DATABASE_URL` at Postgres (`postgresql+psycopg://user:pass@host/wdash`
   — `postgresql://` works too), check that it starts and you can sign in,
   then drop the PVC and its mounts;
3. move the `alerts` container into a Deployment of its own with `replicas: 1`
   — run exactly one, or the same rule pages twice;
4. `strategy: RollingUpdate` and as many replicas as you like.

A source saved on the configuration page reaches every replica within five
seconds without a restart — the worker that handled the save is correct
immediately, and every other one notices on its next poll. The workers do not
need to be recycled to pick one up.

## Network

`networkpolicy.yaml` says who may reach WDash: the ingress controller, and
WDash's own agents. It deliberately says nothing about where WDash may talk —
the identity provider, the backends and an alert channel's webhook are all
chosen after the policy is applied, and a rule that silently stops an alert
being delivered is worse than no rule.

The other half is not ours to apply. Application-level authorization is
worthless if Elasticsearch is reachable around WDash, and that policy belongs
in the cluster's own namespace; there is a template at the bottom of the file.

## The files

| File | What it holds |
| --- | --- |
| `namespace.yaml` | the namespace, labelled so a policy elsewhere can name it |
| `serviceaccount.yaml` | an account with no API token and no permissions |
| `secrets.yaml` | two empty keys, both required, and the commands that fill them |
| `configmap.yaml` | every setting, and the sidecar's nginx.conf |
| `wdash-deployment.yaml` | the pod, the Service and the volume claim |
| `ingress.yaml` | a plain `networking.k8s.io/v1` Ingress, TLS required |
| `networkpolicy.yaml` | who may reach the pod |
| `wdash-agent.yaml` | a probe agent; needs a token, so not applied by default |

`tests/test_kubernetes_manifests.py` holds all of it against the application —
that every ConfigMap key reaches the process, that every volume the pod mounts
is one it declares and every ConfigMap a volume names is one these files
define, that something evaluates the alert rules, and that the proxy count
matches the number of proxies these files describe.

**This page is held too, and it was not before.** It said the sidecar was on
port 80 while the Deployment, the Service, the NetworkPolicy and the
nginx.conf all said 8080, and nothing caught it because nothing read this
file. Now: the ports in the table above are checked against the pod's own
`containerPort`s; the hand-over the first sign-in makes is measured by
claiming a real installation and reading where it redirects to; the recovery
flags are checked against the parsers that accept them; and what this page and
`secrets.yaml` say about an empty `encryption-key` is checked against the
sentence the application logs. A comment nothing checks is how this directory
drifted the first time.
