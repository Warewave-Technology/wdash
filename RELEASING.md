# Releasing WDash

For whoever cuts the release. The process is short on purpose, and the
parts that are checked by a test are checked because a person doing them by
hand gets them wrong on the release where it matters.

Step 4 is the one CI also does. `.github/workflows/tests.yml` runs both
suites on four Pythons, on PostgreSQL, and builds both images on every push
to `github.com/Warewave-Technology/wdash`; it found three defects on its
first run that a single machine could not. Everything else below is still a
command somebody types, and step 6 is the one no test replaces.

## Before the tag

1. **Write the changelog entry.** `CHANGELOG.md`, following the policy in
   its own header. The *Needs action* section is the one people actually
   read — anything that stops working, changes what a setting means, or has
   to be done before the upgrade goes there, at the top.

2. **Bump the version, before the tag and not after.** One number, in
   `src/wdash/__init__.py`. Six other places have to agree with it and a
   test holds each one:

   | Where | Why it has to move |
   |---|---|
   | `package.json`, `package-lock.json` (two copies) | npm writes the root version into the lockfile too, and does not complain when they differ |
   | `kubernetes/wdash-deployment.yaml` | the image the manifests pull |
   | `kubernetes/wdash-agent.yaml` | the same image under a different entry point |
   | `kubernetes/README.md` | the `docker build` lines somebody copies |
   | `SECURITY.md` | which line is supported |

   ```bash
   ./venv/bin/python -m unittest tests.test_version
   ```

3. **Regenerate the third-party notices.**

   ```bash
   ./venv/bin/python tools/third_party_notices.py
   ./venv/bin/python -m unittest tests.test_release_files
   ```

   It reads installed metadata, so run it in an environment built from
   `requirements.txt` — the versions in the file are the versions that ship.

4. **Run both suites, on both dialects.**

   ```bash
   cd lab && ./lab.sh demo && cd ..
   ./venv/bin/python -m tests.run
   WDASH_TEST_POSTGRES=postgresql://wdash:wdash-lab@localhost:55432/wdash \
       ./venv/bin/python -m tests.run
   ```

   Seed the lab first. The lab-backed tests ask about the last 24 hours and
   skip when there is nothing there, naming the command — a run full of
   skips is a run that measured nothing. `./lab.sh targets` says what each
   backend holds.

5. **Build both images and check the small one is small.**

   ```bash
   docker build -t wdash-elastic-dashboard:$(./venv/bin/python -c \
       "import sys; sys.path.insert(0,'src'); import wdash; print(wdash.__version__)") \
       --target server .
   docker build -t wdash-browser:$(...) --target browser .
   docker images | grep wdash
   ```

   **Check the ratio rather than the number, and say which number you
   mean.** There are three, and they are three questions rather than a mess
   to tidy up. Measured for 3.1.1:

   | | server | browser |
   |---|---|---|
   | registry, `linux/amd64` — what you wait for | 79MB | 557MB |
   | registry, `linux/arm64` | 81MB | 592MB |
   | `docker images`, unpacked on this machine | 370MB | 2.39GB |

   The last row depends on the storage driver (containerd's overlayfs
   snapshotter here) and is the one `docker images` prints, which is why it
   is the one that gets quoted by accident. Measure all three again at
   every release rather than carrying them forward: 3.0.0's registry
   figures were 2MB light by 3.1.1. The figures this file carried
   before — 260MB and 1.77GB — match none of the three, and the 2.4.1 image
   built on this machine measures 375MB unpacked against the 260MB its own
   README claimed, so that gap was the measurement environment rather than
   anything a release changed.

   What the check is really for survives all of that: **the server image is
   about a seventh of the browser one.** A server image that has grown
   towards the browser one means the browser stage leaked into it, and
   anybody running a probe for HTTP checks pulls Chromium.

6. **Start it from nothing, the way a reader will.**

   ```bash
   cp .env.example .env     # fill in the two keys
   docker compose up -d
   open http://localhost:5001
   ```

   First-run setup, an authenticator, one source added on the page. If any
   of that needs a step the README does not have, the README is what to fix
   before tagging.

## The tag

```bash
git tag -a v3.1.1 -m "WDash 3.1.1"
git push origin main
git push origin v3.1.1
```

The tag message is not the release notes. `CHANGELOG.md` is.

## After the tag

1. **Push the images**, for both architectures. Step 5 built for this
   machine's; a release has to carry `amd64` too, and `buildx` is what
   makes one manifest naming both.

   ```bash
   docker buildx build --builder wdash --platform linux/amd64,linux/arm64 \
       --target server  -t yigitbasalma/wdash-elastic-dashboard:3.1.1 --push .
   docker buildx build --builder wdash --platform linux/amd64,linux/arm64 \
       --target browser -t yigitbasalma/wdash-browser:3.1.1 --push .
   ```

   Then read back what landed, because the sizes in step 5 are this
   machine's and the table there is the registry's:

   ```bash
   docker buildx imagetools inspect yigitbasalma/wdash-elastic-dashboard:3.1.1
   ```

   `kubernetes/README.md` has the lines for mirroring that into a private
   registry, which is a different job. Push the browser image only if
   anybody runs browser journeys.

2. **Publish the notes**, from the changelog entry, verbatim.

   ```bash
   gh release create v3.1.1 --title "WDash 3.1.1" \
       --notes-file notes.md --latest --verify-tag
   ```

   Verbatim means the section body with its own `## 3.1.1 — <date>` line
   dropped, because the release title already says that. `--verify-tag`
   refuses to invent a tag that does not exist, which is the mistake this
   step can make: `gh` will otherwise create one at whatever HEAD happens
   to be.

   This step was skipped for 3.0.0 and 3.1.0 — both tagged, neither with
   notes — and nothing noticed, because the tag is what the manifests and
   the images refer to and the notes are only for people. Backfilled at
   3.1.1, with `--latest=false` on the two older ones so the newest stays
   the one GitHub offers.

3. **Check the manifests deploy what was pushed.** `tests/test_version.py`
   holds the tag in the YAML to the package version, and nothing holds
   either one to what is in the registry — that is this step.

## What is not in this process, and why

- **Signing.** No image signing, no provenance attestation. Worth adding;
  not pretended to be here.
- **A published SBOM.** `THIRD-PARTY-NOTICES.md` is the licence half of it
  and not the vulnerability half.
- **Anything automatic past the tests.** `.github/workflows/tests.yml`
  covers step 4 on nine jobs; the version bump, the images, the tag and the
  notes are all still typed, and stay that way until somebody writes down
  here what the automatic version would do.
