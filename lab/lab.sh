#!/usr/bin/env bash
#
# WDash lab environment.
#
#   ./lab.sh demo             one command: start every target that holds
#                             data, wait for each, seed it, and print what to
#                             type into WDash
#   ./lab.sh up [target...]    start the stack, or exactly the named targets
#   ./lab.sh seed [target...] [args...]
#                             load sample data. With no target named, every
#                             backend that is running; with one, that one, and
#                             the remaining arguments go to its seeder
#   ./lab.sh targets          what is up, what is in it over the last 24
#                             hours, and what to type into WDash to read it
#   ./lab.sh status           cluster health and index list
#   ./lab.sh logs [service]   container logs
#   ./lab.sh down             stop, keeping data
#   ./lab.sh reset            stop and delete ALL data
#
# Targets: elasticsearch, loki, victorialogs, jaeger, tempo, synthetics,
#          identity, postgres, otel, kibana, cluster
#
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$LAB_DIR"

# Read .env — ES_PORT and friends are needed here too
set -a
# shellcheck disable=SC1091
[ -f .env ] && source .env
set +a

ES_URL="http://localhost:${ES_PORT:-9200}"
LOKI_URL="http://localhost:${LOKI_PORT:-3100}"
VICTORIALOGS_URL="http://localhost:${VICTORIALOGS_PORT:-9428}"
JAEGER_URL="http://localhost:${JAEGER_PORT:-16686}"
TEMPO_URL="http://localhost:${TEMPO_PORT:-3200}"

if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
else
    echo "docker compose not found." >&2
    exit 1
fi

# --------------------------------------------------------------------------
# Targets
#
# One name per thing that can be started, seeded and pointed at on its own.
# WDash reads five of them and each is a different adapter; bringing them up
# together is convenient and it is also how a bug in one gets read as a bug in
# the page. `./lab.sh up loki` starts a Loki and nothing else, so what the
# screen then shows came from the Loki.
#
# bash 3.2 is the macOS default and has no associative arrays, so this is a
# case rather than a map.
# --------------------------------------------------------------------------

#: Everything `up` accepts, in the order `targets` prints them.
ALL_TARGETS="elasticsearch loki victorialogs jaeger tempo synthetics identity postgres otel kibana cluster"

#: The ones with a seeder behind them.
DATA_TARGETS="elasticsearch loki victorialogs jaeger tempo"

#: How long `demo` waits for one backend to become ready before moving on.
#: Elasticsearch is the slow one from cold — measured at around 40s on a
#: laptop with nothing cached — and a demo that gives up at 30 is a demo
#: that fails on the machine it is most needed on.
DEMO_WAIT_SECONDS="${DEMO_WAIT_SECONDS:-180}"

target_known() {
    case " $ALL_TARGETS " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# The compose profile a target lives behind, if any. Elasticsearch has none:
# it is what `./lab.sh up` with no argument starts.
target_profile() {
    case "$1" in
        elasticsearch) echo "" ;;
        cluster)       echo "cluster" ;;
        *)             echo "$1" ;;
    esac
}

# The compose services to start for a target. Named explicitly rather than
# letting `up` start everything, which is what made "start just this one"
# impossible before.
target_services() {
    case "$1" in
        elasticsearch) echo "elasticsearch" ;;
        loki)          echo "loki" ;;
        victorialogs)  echo "victorialogs" ;;
        jaeger)        echo "jaeger" ;;
        tempo)         echo "tempo" ;;
        # Heartbeat writes into Elasticsearch, so compose starts that too.
        synthetics)    echo "synthetics-targets heartbeat" ;;
        identity)      echo "openldap dex" ;;
        postgres)      echo "postgres" ;;
        otel)          echo "otel-collector" ;;
        kibana)        echo "kibana" ;;
        cluster)       echo "elasticsearch2" ;;
    esac
}

target_url() {
    case "$1" in
        elasticsearch) echo "$ES_URL" ;;
        loki)          echo "$LOKI_URL" ;;
        victorialogs)  echo "$VICTORIALOGS_URL" ;;
        jaeger)        echo "$JAEGER_URL" ;;
        tempo)         echo "$TEMPO_URL" ;;
        kibana)        echo "http://localhost:${KIBANA_PORT:-5601}" ;;
        otel)          echo "localhost:${OTLP_GRPC_PORT:-4317} (gRPC), ${OTLP_HTTP_PORT:-4318} (HTTP)" ;;
        identity)      echo "ldap://localhost:${LDAP_PORT:-1389}, http://localhost:${DEX_PORT:-5556}/dex" ;;
        postgres)      echo "postgresql+psycopg://wdash:wdash-lab@localhost:${POSTGRES_PORT:-55432}/wdash" ;;
        synthetics)    echo "http://localhost:18080 and five more" ;;
        # No published port: it joins the cluster on the compose network, and
        # what it changes is visible at the Elasticsearch address above.
        cluster)       echo "a second data node, at $ES_URL" ;;
    esac
}

# Reachable right now? Asked of the service itself rather than of docker, so a
# container that is up and not yet serving reads as not ready — which is what
# a seeder about to write into it needs to know.
target_ready() {
    case "$1" in
        elasticsearch) curl -sf -o /dev/null "$ES_URL/_cluster/health" ;;
        loki)          curl -s "$LOKI_URL/ready" 2>/dev/null | grep -qi ready ;;
        victorialogs)  curl -s "$VICTORIALOGS_URL/health" 2>/dev/null | grep -q OK ;;
        jaeger)        curl -s "$JAEGER_URL/api/services" 2>/dev/null | grep -q data ;;
        tempo)         curl -s "$TEMPO_URL/ready" 2>/dev/null | grep -q "^ready" ;;
        kibana)        curl -sf -o /dev/null "http://localhost:${KIBANA_PORT:-5601}/api/status" ;;
        postgres)      docker exec wdash-lab-postgres pg_isready -U wdash -d wdash >/dev/null 2>&1 ;;
        identity)      curl -s "http://localhost:${DEX_PORT:-5556}/dex/.well-known/openid-configuration" 2>/dev/null | grep -q issuer ;;
        synthetics)    curl -s "http://localhost:18080/" 2>/dev/null | grep -q ok ;;
        otel|cluster)  docker inspect -f '{{.State.Running}}' "$(container_of "$1")" 2>/dev/null | grep -q true ;;
    esac
}

container_of() {
    case "$1" in
        otel)    echo "wdash-lab-otel" ;;
        cluster) echo "wdash-lab-es02" ;;
    esac
}

commas() {
    awk '{ n=$0; s=""; while (length(n) > 3) {
               s = "," substr(n, length(n) - 2) s; n = substr(n, 1, length(n) - 3)
           } print n s }'
}

# What is in a target over the last 24 hours — the window the pages open on.
# An all-time count would say "there is data" about a lab whose data aged out
# of every screen, which is the one mistake this line exists to prevent.
#
# Each phrase carries its own window, because they are not the same window:
# Jaeger will not count traces at all and answers with its service list, which
# is everything it holds.
target_volume() {
    local now start
    now="$(date +%s)"
    start="$((now - 86400))"
    case "$1" in
        elasticsearch)
            local logs traces
            logs="$(curl -s -H 'Content-Type: application/json' \
                "$ES_URL/*logs*/_count" \
                -d '{"query":{"range":{"@timestamp":{"gte":"now-24h"}}}}' \
                | sed -n 's/.*"count":\([0-9]*\).*/\1/p')"
            traces="$(curl -s -H 'Content-Type: application/json' \
                "$ES_URL/*traces*,*apm*/_count" \
                -d '{"query":{"range":{"@timestamp":{"gte":"now-24h"}}}}' \
                | sed -n 's/.*"count":\([0-9]*\).*/\1/p')"
            echo "$(echo "${logs:-0}" | commas) logs and $(echo "${traces:-0}" | commas) trace spans in the last 24 hours"
            ;;
        loki)
            # Loki reports no match count for a range query; an instant
            # count_over_time is the only number it will give.
            local n
            n="$(curl -sG "$LOKI_URL/loki/api/v1/query" \
                --data-urlencode 'query=sum(count_over_time({service_name=~".+"}[24h]))' \
                2>/dev/null | sed -n 's/.*"value":\[[0-9.]*,"\([0-9]*\)".*/\1/p')"
            echo "$(echo "${n:-0}" | commas) lines in the last 24 hours"
            ;;
        victorialogs)
            local n
            n="$(curl -sG "$VICTORIALOGS_URL/select/logsql/query" \
                --data-urlencode 'query=_time:24h | count()' 2>/dev/null \
                | sed -n 's/.*"count(\*)":"\([0-9]*\)".*/\1/p')"
            echo "$(echo "${n:-0}" | commas) lines in the last 24 hours"
            ;;
        jaeger)
            # Jaeger has no count endpoint and its storage here is in memory.
            # The service list is what it will answer cheaply, so that is what
            # is reported — as services, not as traces.
            local n
            n="$(curl -s "$JAEGER_URL/api/services" 2>/dev/null \
                | sed -n 's/.*"total":\([0-9]*\).*/\1/p')"
            echo "${n:-0} services, all it holds"
            ;;
        tempo)
            # Bounded by the limit, so it is a floor and says so. Tempo only
            # makes a new block searchable after it flushes, which takes a few
            # minutes — a fresh seed reads as 0 here for that long.
            local n
            n="$(curl -sG "$TEMPO_URL/api/search" --data-urlencode 'q={}' \
                --data-urlencode "start=$start" --data-urlencode "end=$now" \
                --data-urlencode 'limit=20' 2>/dev/null \
                | grep -o '"traceID"' | wc -l | tr -d ' ')"
            [ "${n:-0}" -ge 20 ] && echo "20+ traces in the last 24 hours" \
                || echo "$((n)) traces in the last 24 hours"
            ;;
        *) echo "" ;;
    esac
}

# What to type into WDash for this target. The form's own defaults are the
# right answer for most fields, and saying "leave it blank" is shorter to
# follow than a pattern list somebody has to compare against the placeholder.
target_form() {
    case "$1" in
        elasticsearch) cat <<EOF
    Configuration → Sources → Add source
      Type     Elasticsearch          Signals  logs, traces, monitors
      URL      $ES_URL
      Leave the three pattern fields blank: the defaults are the lab's
      (*traces*/*apm* for traces, heartbeat-*/synthetics-* for monitors).
EOF
            ;;
        loki) cat <<EOF
    Configuration → Sources → Add source
      Type     Grafana Loki           Signals  logs
      URL      $LOKI_URL
      Leave Tenant and Stream label blank — the seed writes service_name.
EOF
            ;;
        victorialogs) cat <<EOF
    Configuration → Sources → Add source
      Type     VictoriaLogs           Signals  logs
      URL      $VICTORIALOGS_URL
      Leave Tenant and Stream field blank — the seed writes service.
EOF
            ;;
        jaeger) cat <<EOF
    Configuration → Sources → Add source
      Type     Jaeger                 Signals  traces
      URL      $JAEGER_URL
EOF
            ;;
        tempo) cat <<EOF
    Configuration → Sources → Add source
      Type     Grafana Tempo          Signals  traces
      URL      $TEMPO_URL
EOF
            ;;
        synthetics) cat <<EOF
    No source of its own. Heartbeat writes its checks into Elasticsearch, so
    the Monitors page fills in as soon as that cluster is added above with
    the monitors signal ticked.
EOF
            ;;
        identity) cat <<EOF
    Configuration → Authentication → LDAP
      Server   ldap://localhost:${LDAP_PORT:-1389}     Base DN  dc=lab,dc=local
      Bind DN  cn=admin,dc=lab,dc=local        Password  hunter2
      Users: alice, bob, carol, dave — password hunter2. alice is in
      cn=admins, which is the group to map onto the admin role.
    Configuration → Authentication → OpenID Connect (the same directory,
    through Dex — at most one of the two can be in force)
      Discovery  http://localhost:${DEX_PORT:-5556}/dex/.well-known/openid-configuration
      Client id  wdash            Client secret  wdash-lab-secret
      Redirect   http://127.0.0.1:5001/auth/callback
EOF
            ;;
        postgres) cat <<EOF
    Not a source: the metadata store. Point WDash at it before first start
      DATABASE_URL=postgresql+psycopg://wdash:wdash-lab@localhost:${POSTGRES_PORT:-55432}/wdash
EOF
            ;;
        otel) cat <<EOF
    Not a source: a collector that writes into Elasticsearch. Applications
    send OTLP to localhost:${OTLP_GRPC_PORT:-4317}; WDash reads the cluster.
EOF
            ;;
        kibana) cat <<EOF
    Not a source: Kibana itself, on http://localhost:${KIBANA_PORT:-5601}, for
    comparing a screen against the thing WDash is an alternative to.
EOF
            ;;
        cluster) cat <<EOF
    Not a source: a second Elasticsearch data node, so the Advisor's shard
    and replica rules have something to be right about.
EOF
            ;;
    esac
}

require_daemon() {
    if ! docker info >/dev/null 2>&1; then
        cat >&2 <<'EOF'
The Docker daemon is not running.

With OrbStack:        open -a OrbStack
With Docker Desktop:  open -a Docker

Run this command again once the daemon is up.
EOF
        exit 1
    fi
}

refuse_unknown() {
    echo "Unknown target: $1" >&2
    echo "Targets: $ALL_TARGETS" >&2
    exit 1
}

wait_for_es() {
    printf "Waiting for Elasticsearch"
    for _ in $(seq 1 90); do
        if curl -s -o /dev/null "$ES_URL/_cluster/health" 2>/dev/null; then
            echo " ready."
            return 0
        fi
        printf "."
        sleep 2
    done
    echo
    echo "Elasticsearch did not start within 180s. Try './lab.sh logs elasticsearch'." >&2
    return 1
}

cmd_up() {
    require_daemon
    local profile_args=() services=()
    for p in "$@"; do
        target_known "$p" || refuse_unknown "$p"
        local profile
        profile="$(target_profile "$p")"
        if [ -n "$profile" ]; then
            profile_args+=(--profile "$profile")
        fi
        # The TLS targets need certificates before nginx starts, and the
        # certificates are generated rather than committed — a repository with
        # a private key in it teaches whoever reads it that this is normal.
        if [ "$p" = "synthetics" ]; then
            bash "$LAB_DIR/synthetics/make-certs.sh"
        fi
        for service in $(target_services "$p"); do
            services+=("$service")
        done
    done

    # bash 3.2 (the macOS default) errors on empty array expansion under
    # set -u; the ${arr[@]+"${arr[@]}"} form is portable.
    #
    # With no target named, no service is named either, which is compose's own
    # "everything not behind a profile" — the Elasticsearch, as before.
    $COMPOSE ${profile_args[@]+"${profile_args[@]}"} up -d \
        ${services[@]+"${services[@]}"}

    # Only when there is an Elasticsearch to wait for. `./lab.sh up loki` used
    # to block for three minutes on a cluster it had not started.
    if [ $# -eq 0 ] || docker inspect -f '{{.State.Running}}' wdash-lab-es01 \
        2>/dev/null | grep -q true; then
        wait_for_es
    fi

    echo
    if [ $# -eq 0 ]; then
        echo "  elasticsearch  $ES_URL"
    else
        for p in "$@"; do
            printf "  %-14s %s\n" "$p" "$(target_url "$p")"
        done
    fi
    echo
    echo "Load sample data with:  ./lab.sh seed ${*:-}"
    echo "What to type into WDash: ./lab.sh targets"
}

# Find an interpreter for seed.py, creating a lab-local venv if needed. Only
# the interpreter path goes to stdout (the caller consumes it); progress
# messages go to stderr.
seed_python() {
    # 1. Honour an explicit choice
    if [ -n "${PYTHON:-}" ]; then
        echo "$PYTHON"
        return
    fi
    # 2. Use the project venv when it exists and has the library
    if [ -x "$LAB_DIR/../venv/bin/python" ] \
        && "$LAB_DIR/../venv/bin/python" -c "import elasticsearch" 2>/dev/null; then
        echo "$LAB_DIR/../venv/bin/python"
        return
    fi
    # 3. Fall back to a lab-local venv
    local venv="$LAB_DIR/.venv"
    if [ ! -x "$venv/bin/python" ]; then
        echo "Creating lab venv ($venv)..." >&2
        python3 -m venv "$venv" >&2
    fi
    if ! "$venv/bin/python" -c "import elasticsearch" 2>/dev/null; then
        echo "Installing dependencies..." >&2
        "$venv/bin/pip" install --quiet --disable-pip-version-check \
            -r "$LAB_DIR/seed/requirements.txt" >&2
    fi
    echo "$venv/bin/python"
}

# One target, with whatever arguments were left over. Each backend gets its
# own script on purpose: three transports in one file makes "which one failed"
# a question you answer by reading code. Each writes DIFFERENT service names,
# so a merged search over three backends visibly draws from all three.
target_seed() {
    local name="$1"
    shift
    case "$name" in
        elasticsearch)
            "$(seed_python)" "$LAB_DIR/seed/seed.py" --url "$ES_URL" "$@" ;;
        loki)
            "$(seed_python)" "$LAB_DIR/seed/seed_loki.py" --url "$LOKI_URL" "$@" ;;
        victorialogs)
            "$(seed_python)" "$LAB_DIR/seed/seed_victorialogs.py" \
                --url "$VICTORIALOGS_URL" "$@" ;;
        jaeger)
            "$(seed_python)" "$LAB_DIR/seed/seed_jaeger.py" \
                --query-url "$JAEGER_URL" \
                --url "http://localhost:${JAEGER_OTLP_PORT:-4319}" "$@" ;;
        tempo)
            "$(seed_python)" "$LAB_DIR/seed/seed_tempo.py" \
                --query-url "$TEMPO_URL" \
                --url "http://localhost:${TEMPO_OTLP_PORT:-4320}" "$@" ;;
        synthetics)
            echo "synthetics has no seeder: Heartbeat is a running agent and" \
                 "writes its own checks into Elasticsearch." ;;
        *)
            echo "$name has no sample data to load." ;;
    esac
}

cmd_seed() {
    require_daemon

    # Leading words are target names; everything from the first option on goes
    # to the seeder. `./lab.sh seed --days 30` therefore still means what it
    # always did, and `./lab.sh seed loki --hours 168` seeds one backend.
    #
    # A string rather than an array: bash 3.2 is the macOS default, and under
    # `set -u` it calls an empty array unset.
    local names=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -*) break ;;
        esac
        target_known "$1" || refuse_unknown "$1"
        names="$names $1"
        shift
    done

    if [ -n "$names" ]; then
        for name in $names; do
            if ! target_ready "$name"; then
                echo "$name is not reachable at $(target_url "$name")." \
                     "Start it with './lab.sh up $name'." >&2
                exit 1
            fi
            target_seed "$name" "$@"
        done
        return
    fi

    # No target named: every backend that is running. Arguments go to the
    # Elasticsearch seeder only — the others take different options, and a
    # --days meant for one would abort the rest.
    local seeded=0
    for name in $DATA_TARGETS; do
        if target_ready "$name"; then
            seeded=1
            if [ "$name" = "elasticsearch" ]; then
                target_seed "$name" "$@"
            else
                target_seed "$name"
            fi
        fi
    done
    if [ "$seeded" -eq 0 ]; then
        echo "No backend is running. Start one with './lab.sh up <target>'." >&2
        echo "Targets with sample data: $DATA_TARGETS" >&2
        exit 1
    fi
}

cmd_targets() {
    require_daemon
    echo
    for name in $ALL_TARGETS; do
        local state volume
        if target_ready "$name"; then
            state="up"
            volume="$(target_volume "$name")"
            if [ -n "$volume" ]; then
                state="up · $volume"
            fi
        else
            state="not running — ./lab.sh up $name"
        fi
        printf "%-14s %s\n" "$name" "$state"
        target_form "$name"
        echo
    done
    cat <<'EOF'
An empty count on a target that is up means its data has aged out of the
window every page opens on. Reload it: ./lab.sh seed <target>
EOF
}

cmd_demo() {
    # The whole lab in one command, for somebody who wants to look at WDash
    # rather than at the lab. `up` then `seed` is two commands with a WAIT
    # between them that nobody is told about: a backend accepts connections
    # before it will accept writes, and seeding a Loki that is up but not
    # ready fails in a way that reads as a broken seeder.
    #
    # Only the targets that HOLD data. Kibana, Dex, Postgres and the otel
    # collector are here for other reasons and have no seeder; starting them
    # for a demo is three more containers and no more to look at.
    require_daemon

    echo "Starting ${DATA_TARGETS} …"
    echo
    # shellcheck disable=SC2086
    cmd_up $DATA_TARGETS

    echo
    for name in $DATA_TARGETS; do
        printf "waiting for %-14s" "$name"
        local waited=0
        until target_ready "$name"; do
            if [ "$waited" -ge "$DEMO_WAIT_SECONDS" ]; then
                echo "not ready after ${DEMO_WAIT_SECONDS}s."
                echo "  Its log may say why: ./lab.sh logs" >&2
                echo "  Seed it yourself once it is: ./lab.sh seed $name" >&2
                # Not fatal. Four backends up and one slow is still a lab
                # worth looking at, and stopping here would throw the other
                # four away over the fifth.
                continue 2
            fi
            sleep 2
            waited=$((waited + 2))
        done
        echo "ready"
        target_seed "$name" "$@"
    done

    echo
    cmd_targets
    cat <<'EOF'
Now put them in WDash. One command, against an installation nobody has
claimed yet — it creates the administrator and adds every backend above
that answered:

    PYTHONPATH=src python -m wdash.demo

It asks for a password and stops there. The first sign-in enrols an
authenticator, which is what every local account does and what a demo is
not allowed to skip. An installation that already has an account is a
refusal, and `--into-claimed` adds the sources to it without touching
the account.

By hand instead: Configuration → Sources → Add source, using the lines
above. Each is one entry; an Elasticsearch serving logs AND traces is ONE
source with both boxes ticked.
EOF
}

cmd_status() {
    require_daemon
    echo "== Cluster =="
    curl -s "$ES_URL/_cluster/health?pretty" || echo "unreachable"
    echo
    echo "== Indices =="
    curl -s "$ES_URL/_cat/indices?v&h=health,status,index,pri,rep,docs.count,store.size&s=index" \
        || echo "unreachable"
    echo
    echo "== Containers =="
    $COMPOSE ps
}

# Every profile, so that `down` stops what `up` started. It named two, and a
# Loki brought up on its own went on running through a stop-the-lab.
every_profile() {
    local args=() profile
    for name in $ALL_TARGETS; do
        profile="$(target_profile "$name")"
        if [ -n "$profile" ]; then
            args+=(--profile "$profile")
        fi
    done
    echo "${args[@]}"
}

cmd_down() {
    require_daemon
    # shellcheck disable=SC2046
    $COMPOSE $(every_profile) down
    echo "Stopped. Data preserved — './lab.sh up' brings it back."
}

cmd_reset() {
    require_daemon
    echo "This will delete ALL data in the lab volumes."
    read -r -p "Continue? [y/N] " answer
    case "$answer" in
        y|Y)
            # shellcheck disable=SC2046
            $COMPOSE $(every_profile) down -v
            echo "Deleted."
            ;;
        *)
            echo "Cancelled."
            ;;
    esac
}

case "${1:-}" in
    demo)    shift; cmd_demo "$@" ;;
    up)      shift; cmd_up "$@" ;;
    seed)    shift; cmd_seed "$@" ;;
    targets) cmd_targets ;;
    status)  cmd_status ;;
    logs)    shift; require_daemon; $COMPOSE logs -f "$@" ;;
    down)    cmd_down ;;
    reset)   cmd_reset ;;
    *)
        sed -n '3,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
        exit 1
        ;;
esac
