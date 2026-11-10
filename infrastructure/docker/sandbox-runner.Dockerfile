# syntax=docker/dockerfile:1.7
# Sandbox runner image (step 4.6 X6, docs/plan/steps/14-sandbox.md; ADR-0039;
# docs/security/sandbox-threat-model.md; docs/security/sandbox-escape-testing.md).
#
# LOCAL/CI ONLY — NOT A VM BOUNDARY. Containers from this image share the Docker VM's kernel. The
# hardened-container backend of the sandbox-controller starts one disposable container per task
# (execute profile: script_shell / script_js) with a verified hardened spec: user 65532, read-only
# root, tmpfs /scratch and /tmp, CapDrop ALL, no-new-privileges, Docker's default seccomp profile,
# no mounts/devices/ports, the internal `sandbox-detonation` network only (DNS = the recording
# sinkhole). Only synthetic benign probes and the EICAR test string (built at run time) are ever
# executed. Production never runs this image.
#
# Contents: the Node.js binary of the pinned node:22-alpine (no npm/yarn/corepack), its two
# shared libraries, strace (behaviour trace) and busybox (the base image's sh), and the trusted
# entrypoint /opt/eg/bootstrap.mjs. No secrets, no build tools, no package manager cache.
# Build (one image at a time on the Docker VM):
#   docker build -f infrastructure/docker/sandbox-runner.Dockerfile -t email-gateway/sandbox-runner:local .
ARG NODE_IMAGE=node:22-alpine@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202
ARG BASE_IMAGE=alpine:3.24@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a

FROM ${NODE_IMAGE} AS node

FROM ${BASE_IMAGE} AS runtime
RUN apk add --no-cache libstdc++ libgcc strace \
 && rm -rf /var/cache/apk/* \
 && mkdir -p /opt/eg /scratch \
 && chmod 0755 /opt/eg \
 && chmod 0700 /scratch \
 && chown 65532:65532 /scratch
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --chmod=0444 infrastructure/sandbox/runner/bootstrap.mjs /opt/eg/bootstrap.mjs
ENV PATH=/usr/local/bin:/usr/bin:/bin
USER 65532:65532
WORKDIR /scratch
LABEL org.opencontainers.image.title="email-gateway sandbox runner (LOCAL/CI ONLY, NOT A VM BOUNDARY)" \
      eg.sandbox.isolation="container-not-vm"
ENTRYPOINT ["/usr/local/bin/node", "/opt/eg/bootstrap.mjs"]
