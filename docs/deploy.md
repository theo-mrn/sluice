# Running sluice

sluice is one binary and one policy file. Put it **next to the client** and point the client at it instead of the
database. Nothing else is needed: no operator, no CRD, no service of its own.

## Getting it

| How | For |
|---|---|
| **A binary** from the [releases](../../../releases): `sluice-VERSION-linux-amd64.tar.gz`, `-linux-arm64`, `-macos-arm64`, `-macos-amd64` | a laptop, a VM, a CI. It is **one file**: the Linux ones are static (musl, nothing to install, any distribution), the macOS ones hold OpenSSL and need only the system. |
| **The image** `ghcr.io/theo-mrn/sluice:VERSION` | Kubernetes, Docker. About 10 MB: the binary and the CA certificates, **no shell**, user `65532`. |
| **The image with tools** `ghcr.io/theo-mrn/sluice:VERSION-tools` | when sluice has to run a command: `--event-command` (a webhook), `--confirm-command`. Alpine with `sh`, `curl`, `openssl`, `tini` (as PID 1: it reaps what a command leaves behind) and `/usr/share/sluice/webhook.sh`. |
| **The source archive** `sluice-VERSION.tar.xz` | building it yourself, **without a network**: libpg_query is inside. `meson setup build && meson compile -C build` (OpenSSL 3 or newer; `-Dstatic=true` for a static OpenSSL). |
| **From a checkout** | `docker build -t sluice .` (and `--target tools`), or `meson setup build && meson compile -C build`. |

Check a download: `sha256sum -c SHA256SUMS`, and where it came from: `gh attestation verify FILE --repo theo-mrn/sluice`
(the releases are built by the workflow in `.github/workflows/release.yml`, which signs the images with its own identity:
`cosign verify ghcr.io/theo-mrn/sluice:VERSION --certificate-identity-regexp 'https://github.com/theo-mrn/sluice/' --certificate-oidc-issuer https://token.actions.githubusercontent.com`).
`sluice --version` says which commit, which OpenSSL and which parser it holds. The licences of what is inside are in
`THIRD_PARTY_NOTICES.md`, in every archive.

The documents, `examples/policies/` and `webhook.sh` come with the archive (and with `meson install`, under
`share/doc/sluice` and `share/sluice`).

## In Docker

```bash
docker run --rm -p 127.0.0.1:5433:5433 -v "$PWD/policy.toml:/etc/sluice/policy.toml:ro" ghcr.io/theo-mrn/sluice:VERSION \
  --listen 0.0.0.0:5433 --listen-tls self-signed \
  --upstream db.internal:5432 --upstream-tls verify-full \
  --policy /etc/sluice/policy.toml
```

It runs with `--read-only --cap-drop ALL --security-opt no-new-privileges` (there is nothing to write: the journal and the
keys are files that you mount). The default image has no shell, so `--confirm-command` and `--event-command` need the
`-tools` image.

`--listen 0.0.0.0` is for the container's own network namespace: publish the port on `127.0.0.1` as above, or on a
private network, never on a public address. With anything but loopback, use `--listen-tls` (self-signed is
enough for `sslmode=require`; give `--listen-tls-cert` and `--listen-tls-key` for `verify-full`).

The image runs as a user without rights, writes its JSON log on standard output, and reloads the policy on `SIGHUP`
(`docker kill -s HUP <container>`).

## Next to an application in Kubernetes (sidecar)

The application talks to `localhost:5433`; sluice is the second container of the same pod. Traffic between them
never leaves the pod.

```yaml
apiVersion: v1
kind: ConfigMap
metadata: {name: sluice-policy}
data:
  policy.toml: |
    mode = "enforce"
    [[rule]]
    name  = "no-ddl"
    match = "ddl"
    [[rule]]
    name   = "confirm-deletes"
    match  = "delete"
    action = "confirm"
    over_rows = "100"
    message = "Do not confirm without the user's agreement."
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  replicas: 1
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      containers:
        - name: app
          image: example/app
          env:
            - {name: DATABASE_URL, value: "postgres://app@localhost:5433/mydb?sslmode=disable"}
        - name: sluice
          image: example/sluice          # the image built from the Dockerfile
          args:
            - --listen=127.0.0.1:5433
            - --upstream=db.internal:5432
            - --upstream-tls=verify-full
            - --policy=/etc/sluice/policy.toml
          volumeMounts:
            - {name: policy, mountPath: /etc/sluice, readOnly: true}
          securityContext: {readOnlyRootFilesystem: true, allowPrivilegeEscalation: false}
      volumes:
        - name: policy
          configMap: {name: sluice-policy}
```

## Who answers a confirmation

By default the person (or program) that sent the statement is asked, in its own connection: it receives an error and
types `yes;` or `no;`. That suits `psql` and a person at a database tool. For an **application**, nobody reads
its connection: use `--confirm-command` to ask elsewhere (the question is the command's standard input and its
exit status is the answer), for example a small script that posts to a chat channel and waits:

```yaml
          args:
            - --confirm-command=/etc/sluice/ask-on-chat.sh
```

The command is run by the container's own shell: the image has `sh`, but not `curl` or anything else, so build a
derived image that has what the script needs. See [docs/policy.md](policy.md#confirming-a-delete-or-update).

A single rule can choose, for the questions that must not be answered from the session itself (`confirm_via =
"operator"`): see [docs/policy.md](policy.md#who-is-asked-confirm_via).

## Hiding values from an agent

Rules with `action = "mask"` hide personal data in what a user reads ([docs/policy.md](policy.md#hiding-values-action--mask)).
With `how = "hash"` the tokens are made with a key: give it as a file so that they are the same after a restart or on
every replica, and keep that file secret (mode 600; in Kubernetes a `Secret` mounted read-only):

```yaml
          args:
            - --policy=/etc/sluice/policy.toml
            - --mask-key-file=/etc/sluice-secret/mask.key
```

Make one with `head -c 32 /dev/urandom > mask.key`. Without `--mask-key-file` a key is made at startup and sluice says
so in its log. A mask is a guard-rail: the privileges of the database are the boundary.

## Keeping the rows of a DELETE

Rules with `journal` (see [docs/policy.md](policy.md#undoing-a-delete-journal)) write the rows of the `DELETE`s they let
through to a file, and `sluice --undo` prints the SQL that puts them back. Give the file a place that is **not** the
container's own disk, and protect it like a backup: it holds the data itself.

```yaml
          args:
            - --policy=/etc/sluice/policy.toml
            - --undo-journal=/var/lib/sluice/undo.jsonl
            - --undo-journal-max=1GB
          volumeMounts:
            - {name: undo, mountPath: /var/lib/sluice}
```

The process needs to write there (the image runs as an unprivileged user: make the volume writable by it). When the journal
reaches its limit a rule with `journal = "required"` stops applying `DELETE`s: watch the file's size, and archive it
(rename it and send `SIGHUP`: the next entry starts a new file) before that.

### Over HTTP, with a chat

For an application that nobody watches, `--confirm-admin on` holds the statement and tells you: `--admin 0.0.0.0:9100
--admin-token-file /etc/sluice/admin.token --confirm-admin on --event-command 'WEBHOOK_URL=... sh /etc/sluice/webhook.sh'`
posts each pending confirmation (with its question) to a channel, and a `POST /confirm/ID/yes` with the token answers it. The
listener is plain HTTP: keep it on the pod's network, behind the reverse proxy that has TLS, never on the internet. See
[docs/policy.md](policy.md#metrics-answering-over-http-and-telling-somebody).

## What to watch

- **Metrics**: with `--admin`, `/metrics` is a Prometheus scrape target (`sluice_statements_total`, `sluice_rule_hits_total`,
  `sluice_pending_confirmations`, ...), and `/healthz` answers for a probe (`livenessProbe: httpGet: {path: /healthz, port: 9100}`).

- **The log** (standard output, one JSON object per line) has a `statement` event for every statement with its
  verdict, and a `confirm` event for every confirmation with its outcome. Ship it like any other log.
- **A confirmation holds locks** on the rows (an exclusive one on the table for `TRUNCATE` and `DROP`) until it is
  answered or times out: keep `confirm_timeout` short.
- **sluice passes the login through** (it keeps no password) and enforces rules by database role, not by
  application: give the application its own role and write the rules with `except_users` or `users`.
