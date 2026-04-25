# sluice in a container, built from source. Two images come out of it:
#
#   docker build -t sluice .                       the default: NOTHING but the binary (and the CA certificates). About
#                                                  8 MB, no shell, no package manager, a numeric non-root user.
#   docker build --target tools -t sluice:tools .  the same binary on Alpine, with a shell, curl, openssl and the webhook
#                                                  command (tools/webhook.sh): what --event-command and --confirm-command
#                                                  need, since the first image has no `sh` to run them.
#
#   docker run --rm sluice --version
#
# The binary is the static one (musl, OpenSSL inside), the same as the release binaries. Meson downloads libpg_query
# (pinned by hash in subprojects/libpg_query.wrap) unless the source tree already holds it (a release archive does).
#
# The releases are built from the binaries that the release workflow already made: see Dockerfile.release.

FROM alpine:3.22 AS build
ARG COMMIT=unknown
RUN apk add --no-cache gcc g++ musl-dev meson samurai pkgconf openssl-dev openssl-libs-static python3 linux-headers binutils
WORKDIR /src
COPY . .
RUN meson setup build --buildtype=release -Db_ndebug=true -Dstatic=true -Dcommit="$COMMIT" \
 && meson compile -C build sluice \
 && strip build/sluice

FROM alpine:3.22 AS tools
RUN apk add --no-cache ca-certificates curl openssl tini \
 && adduser -D -H -u 65532 -s /sbin/nologin sluice
COPY --from=build /src/build/sluice /usr/local/bin/sluice
COPY tools/webhook.sh /usr/share/sluice/webhook.sh
USER 65532:65532
# tini reaps what a command started by --event-command leaves behind
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/sluice"]

FROM scratch AS runtime
COPY --from=tools /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/build/sluice /sluice
LABEL org.opencontainers.image.title="sluice" \
      org.opencontainers.image.description="A guard proxy for PostgreSQL" \
      org.opencontainers.image.licenses="MIT"
# A number, not a name: Kubernetes (runAsNonRoot) cannot check a name in an image with no /etc/passwd.
USER 65532:65532
# Not a PostgreSQL port on purpose: give --listen and --upstream, and mount the policy.
ENTRYPOINT ["/sluice"]
