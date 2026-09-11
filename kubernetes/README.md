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

Four things, and none of them start without you.

**0. The image.** The manifests name
`yigitbasalma/wdash-elastic-dashboard:2.4.1`, and the published images stop at
2.2.4 — an apply of these files as they are pulls a tag that does not exist,
and every container waits in `ErrImagePull`. Build this version and push it
where your cluster can pull from, then point the manifests at it:

```bash
docker build -t <registry>/wdash-elastic-dashboard:2.4.1 --target server .
docker push <registry>/wdash-elastic-dashboard:2.4.1
cd kubernetes && kustomize edit set image \
    yigitbasalma/wdash-elastic-dashboard=<registry>/wdash-elastic-dashboard:2.4.1
```

`wdash-agent.yaml` is not part of the kustomization; set its `image:` by hand.

**1. The two secrets.** Both are empty on purpose. `secret-key` used to ship as
a working key printed in this repository, so an unedited apply signed every
session cookie — including the administrator's — with a string anybody can
read. The application now refuses to start on its development key while
`SESSION_COOKIE_SECURE` is true, so an unfilled Secret fails with a message
rather than quietly running forgeable.

```bash
kubectl create namespace wdash

kubectl -n wdash create secret generic wdash-secrets \
    --from-literal=secret-key="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')" \
    --from-literal=encryption-key="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
    --from-literal=oidc-client-secret="" \
    --from-literal=elasticsearch-username="" \
    --from-literal=elasticsearch-password=""
```

Back the encryption key up with the database and not separately from it.
Changing it later makes every stored credential undecryptable — source
passwords, the OIDC client secret, the LDAP bind password.

`secrets.yaml` is a template and the kustomization does not apply it: an
apply would overwrite whatever you created here with empty values, and the
next restart would refuse to start on a session key it no longer had. Create
the Secret once, keep the file as the record of what goes in it.

**2. The hostname**, in two files that have to agree: the `host` and `tls`
entries in `ingress.yaml`, and `OIDC_REDIRECT_URI` in `configmap.yaml`. A
mismatch surfaces as the identity provider refusing an unknown redirect URI,
which names neither file.

**3. `ELASTICSEARCH_URL`** in `configmap.yaml`, unless your cluster really is
at `http://elasticsearch:9200` in this namespace. Set it to nothing if this
deployment reads from Loki or VictoriaLogs instead — the configuration page
declares those, and an environment source pointing at a cluster that is not
there is a source that fails on every search.

## Apply

```bash
kubectl apply -k kubernetes/
kubectl -n wdash rollout status deploy/wdash
```

Then open the hostname. The first visit lands on `/setup`, which claims the
installation with a local administrator account; every route redirects there
until it does. That account keeps working when the identity provider does not,
which is exactly what makes it worth protecting.

## What is in the pod

| Container | What it is |
| --- | --- |
| `wdash` | gunicorn, four workers, on port 5000 |
| `alerts` | `python -m wdash.alerts`, evaluating rules every 30 seconds |
| `nginx` | the sidecar on port 80: static files, and the proxy in front |

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

## Probes

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

Browser journeys need the browser image, which is 1.77GB against 260MB and is
not published:

```bash
docker build -t <registry>/wdash-browser:2.4.1 --target browser .
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

   It refuses a target that holds anything, counts both sides afterwards,
   and copies the sealed credentials as they are — so keep the same
   `encryption-key` in the Secret;
2. point `DATABASE_URL` at Postgres (`postgresql+psycopg://user:pass@host/wdash`
   — `postgresql://` works too), check that it starts and you can sign in,
   then drop the PVC and its mounts;
3. move the `alerts` container into a Deployment of its own with `replicas: 1`
   — run exactly one, or the same rule pages twice;
4. `strategy: RollingUpdate` and as many replicas as you like.

A source saved on the configuration page reaches every replica within a few
seconds without a restart, so the workers do not need to be recycled to pick
one up.

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
| `secrets.yaml` | two empty keys and the commands that fill them |
| `configmap.yaml` | every setting, the roles imported on first boot, the sidecar's nginx.conf |
| `wdash-deployment.yaml` | the pod, the Service and the volume claim |
| `ingress.yaml` | a plain `networking.k8s.io/v1` Ingress, TLS required |
| `networkpolicy.yaml` | who may reach the pod |
| `wdash-agent.yaml` | a probe agent; needs a token, so not applied by default |

`tests/test_kubernetes_manifests.py` holds all of it against the application —
that every ConfigMap key reaches the process, that the roles file still parses
under the schema the importer reads, that something evaluates the alert rules,
and that the proxy count matches the number of proxies these files describe.
