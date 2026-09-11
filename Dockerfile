# Two images from one file.
#
#   wdash            the server, and an agent that runs http and tcp checks
#   wdash-browser    the same code plus Chromium, for browser journeys
#
# Measured: 260MB and 1.77GB. That ratio is the whole reason for the split.
# Phase 2 settled on "same image, different entry point" for the agent and
# that still holds for http and tcp; a journey broke the rule for a concrete
# reason rather than a tidy one — everybody running a single probe for uptime
# checks would otherwise carry a gigabyte and a half of browser to do it.
#
#   docker build -t wdash .
#   docker build -t wdash-browser --target browser .
#
# `server` is LAST on purpose. A build with no `--target` takes the final
# stage, and with the order the other way round `docker build .` quietly
# produced the browser image — six times the size, and an entry point that is
# an agent rather than the server.

FROM python:3.11-slim AS base

WORKDIR /app

# The package lives at /app/src/wdash and nothing installs it, so without
# this `wdash` is importable only by main.py, which puts src on the path
# itself — that is, only by gunicorn. Everything else this image and the
# manifests start is `python -m wdash.<something>`: the alert evaluator in
# the Kubernetes pod, the agent, the browser image's entry point. Each one
# died at start with "No module named wdash", and the pod with it, while the
# CI image job passed — because it put src on the path by hand before it
# imported anything.
ENV PYTHONPATH=/app/src

# No gcc. Every pinned dependency ships a manylinux wheel — measured with
# `pip install --only-binary=:all:` against this exact base image — so the
# compiler was only ever adding weight and attack surface to a published
# image. If a future dependency needs to build, add it back in a builder
# stage rather than here.

# Requirements first, so a code change does not reinstall the world.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code. What this does NOT copy is in .dockerignore, and it
# matters: without it this line baked .env and data/wdash.db into the image —
# the encryption key and the credentials it decrypts, together, in something
# published to a registry.
COPY . .

# Create non-root user
RUN useradd -m -u 1000 wdash && chown -R wdash:wdash /app
USER wdash


# ---------------------------------------------------------------------------
# The browser agent
# ---------------------------------------------------------------------------

FROM base AS browser

USER root

# Chromium and the libraries it needs, installed by Playwright itself rather
# than by an apt list written out here. The list changes per release, and one
# written by hand goes stale as a missing shared library at start-up — which
# surfaces as "the browser could not start" on a probe somebody deployed six
# months later.
#
# The version is pinned, and not only for reproducibility: `--with-deps` on
# 1.49 asks for `ttf-unifont` and `ttf-ubuntu-font-family`, which are Ubuntu
# package names that Debian bookworm does not have, and the build fails with
# "Failed to install browsers". 1.62 asks for names this base actually has.
#
# PLAYWRIGHT_BROWSERS_PATH is set BEFORE the install, so the browser is
# unpacked where it will be read from. Installing into root's cache and
# copying it afterwards produced a 2.8GB image: the copy is a new layer and
# the original stays in the one below it, so the browser shipped twice. Same
# result, 1.77GB.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright

RUN pip install --no-cache-dir playwright==1.62.0 \
    && playwright install --with-deps chromium \
    && chown -R wdash:wdash /opt/playwright \
    && rm -rf /var/lib/apt/lists/* /root/.cache

USER wdash

# No HEALTHCHECK: this image serves nothing. Whether the agent is alive is a
# question the SERVER answers — `last_seen_at` on the agents page, and the
# agent_silent alert rule. A probe reporting its own health is a probe
# reporting that it can reach itself.
HEALTHCHECK NONE

# The agent, not gunicorn. Same code, different entry point — the part of the
# phase 2 rule that survived.
ENTRYPOINT ["python", "-m", "wdash.agent"]


# ---------------------------------------------------------------------------
# The server (default)
# ---------------------------------------------------------------------------

FROM base AS server

EXPOSE 5000

# Health check.
#
# NOT curl: python:3.11-slim does not have it, so the previous check failed
# every time and the container was permanently unhealthy. Nothing in
# Kubernetes noticed — its probes are httpGet — but `docker run` reported
# unhealthy for ever, and a compose service waiting on
# `condition: service_healthy` would never start. Python is the one program
# this image is guaranteed to have.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:5000/health', timeout=5).status == 200 else 1)"

# Run application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "main:app"]
