FROM python:3.11-slim

WORKDIR /app

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

# Expose port
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
