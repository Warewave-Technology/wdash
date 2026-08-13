#!/usr/bin/env bash
#
# WDash lab environment.
#
#   ./lab.sh up [profile...]   start the stack
#                             profiles: kibana, cluster, otel, loki, victorialogs,
#                                       synthetics (Heartbeat + probe targets),
#                                       jaeger, tempo
#   ./lab.sh seed [args...]    load sample data into every running backend
#                             (args go to seed.py; Loki and VictoriaLogs are
#                              seeded too when their profiles are up)
#   ./lab.sh status            cluster health and index list
#   ./lab.sh logs [service]    container logs
#   ./lab.sh down              stop, keeping data
#   ./lab.sh reset             stop and delete ALL data
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

if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
else
    echo "docker compose not found." >&2
    exit 1
fi

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
    local profile_args=()
    for p in "$@"; do
        profile_args+=(--profile "$p")
        # The TLS targets need certificates before nginx starts, and the
        # certificates are generated rather than committed — a repository with
        # a private key in it teaches whoever reads it that this is normal.
        if [ "$p" = "synthetics" ]; then
            bash "$(dirname "$0")/synthetics/make-certs.sh"
        fi
    done

    # bash 3.2 (the macOS default) errors on empty array expansion under
    # set -u; the ${arr[@]+"${arr[@]}"} form is portable.
    $COMPOSE ${profile_args[@]+"${profile_args[@]}"} up -d
    wait_for_es

    echo
    echo "  Elasticsearch  $ES_URL"
    for p in "$@"; do
        [ "$p" = "kibana" ] && echo "  Kibana         http://localhost:${KIBANA_PORT:-5601}"
        [ "$p" = "otel" ]   && echo "  OTLP           localhost:${OTLP_GRPC_PORT:-4317} (gRPC), ${OTLP_HTTP_PORT:-4318} (HTTP)"
        [ "$p" = "loki" ]   && echo "  Loki           http://localhost:${LOKI_PORT:-3100}"
        [ "$p" = "victorialogs" ] && echo "  VictoriaLogs   http://localhost:${VICTORIALOGS_PORT:-9428}"
        [ "$p" = "jaeger" ] && echo "  Jaeger         http://localhost:${JAEGER_PORT:-16686}"
        [ "$p" = "tempo" ] && echo "  Tempo          http://localhost:${TEMPO_PORT:-3200}"
    done
    echo
    echo "Load sample data with:  ./lab.sh seed"
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

cmd_seed() {
    require_daemon
    if ! curl -s -o /dev/null "$ES_URL/_cluster/health" 2>/dev/null; then
        echo "Elasticsearch is not reachable. Run './lab.sh up' first." >&2
        exit 1
    fi

    ELASTICSEARCH_URL="$ES_URL" "$(seed_python)" "$LAB_DIR/seed/seed.py" "$@"

    # The other backends, when they happen to be running. Skipped quietly
    # rather than failing: `./lab.sh up` without a profile starts neither, and
    # refusing to seed Elasticsearch because Loki is absent would be silly.
    #
    # Each one writes DIFFERENT service names on purpose. A merged search over
    # three backends that all say "api-gateway" cannot show you that the merge
    # is working.
    local loki_url="http://localhost:${LOKI_PORT:-3100}"
    if curl -s "$loki_url/ready" 2>/dev/null | grep -qi ready; then
        "$(seed_python)" "$LAB_DIR/seed/seed_loki.py" --url "$loki_url"
    fi

    local vl_url="http://localhost:${VICTORIALOGS_PORT:-9428}"
    if curl -s "$vl_url/health" 2>/dev/null | grep -q OK; then
        "$(seed_python)" "$LAB_DIR/seed/seed_victorialogs.py" --url "$vl_url"
    fi

    local jaeger_url="http://localhost:${JAEGER_PORT:-16686}"
    if curl -s "$jaeger_url/api/services" 2>/dev/null | grep -q data; then
        "$(seed_python)" "$LAB_DIR/seed/seed_jaeger.py" \
            --query-url "$jaeger_url" \
            --url "http://localhost:${JAEGER_OTLP_PORT:-4319}"
    fi

    local tempo_url="http://localhost:${TEMPO_PORT:-3200}"
    if curl -s "$tempo_url/ready" 2>/dev/null | grep -q "^ready"; then
        "$(seed_python)" "$LAB_DIR/seed/seed_tempo.py" \
            --query-url "$tempo_url" \
            --url "http://localhost:${TEMPO_OTLP_PORT:-4320}"
    fi
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

cmd_down() {
    require_daemon
    $COMPOSE --profile kibana --profile cluster down
    echo "Stopped. Data preserved — './lab.sh up' brings it back."
}

cmd_reset() {
    require_daemon
    echo "This will delete ALL data in the lab volumes."
    read -r -p "Continue? [y/N] " answer
    case "$answer" in
        y|Y)
            $COMPOSE --profile kibana --profile cluster down -v
            echo "Deleted."
            ;;
        *)
            echo "Cancelled."
            ;;
    esac
}

case "${1:-}" in
    up)     shift; cmd_up "$@" ;;
    seed)   shift; cmd_seed "$@" ;;
    status) cmd_status ;;
    logs)   shift; require_daemon; $COMPOSE logs -f "$@" ;;
    down)   cmd_down ;;
    reset)  cmd_reset ;;
    *)
        sed -n '3,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
        exit 1
        ;;
esac
