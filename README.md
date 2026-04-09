# Avro Decompression Bomb PoC (CWE-409)

Proof of concept demonstrating a **decompression bomb** vulnerability in
[Apache Avro](https://github.com/apache/avro)'s Java codec layer.

A crafted Avro file that is **50 KB on disk** decompresses to **50 MB** at
read time, causing `java.lang.OutOfMemoryError` and crashing the JVM. The
root cause is that every compression codec in Avro decompresses into an
**unbounded `ByteArrayOutputStream`** with no size limit.

> **Upstream PR:** <https://github.com/apache/avro/pull/3625>

---

## Table of contents

1. [Vulnerability summary](#vulnerability-summary)
2. [Affected versions and components](#affected-versions-and-components)
3. [Technical root cause](#technical-root-cause)
4. [Multi-codec proof](#multi-codec-proof)
5. [The crafted `.avro` file](#the-crafted-avro-file)
6. [How the PoC works](#how-the-poc-works)
7. [Quick start -- Docker](#quick-start----docker)
8. [Quick start -- local Maven](#quick-start----local-maven)
9. [Expected output](#expected-output)
10. [PR #3625 analysis](#pr-3625-analysis)
11. [Project structure](#project-structure)
12. [Prerequisites](#prerequisites)
13. [Impact assessment](#impact-assessment)
14. [Suggested mitigation](#suggested-mitigation)
15. [References](#references)

---

## Vulnerability summary

| Field           | Value                                                        |
| --------------- | ------------------------------------------------------------ |
| **Type**        | Denial of Service (DoS)                                      |
| **CWE**         | CWE-409 -- Improper Handling of Highly Compressed Data        |
| **Severity**    | High                                                         |
| **Attack vector** | Malicious Avro file supplied to any Avro reader            |
| **Library**     | `org.apache.avro:avro` (Java)                                |
| **Tested version** | 1.12.0 (also affects latest `main` at time of writing)    |
| **Affected codecs** | Deflate, Zstandard, BZip2, Snappy, XZ                   |

---

## Affected versions and components

Every release of Apache Avro Java that contains `DataFileReader` /
`DataFileStream` is affected, because the codec `decompress()` path has
**never** had a size limit. The following classes are directly vulnerable:

| Codec class          | Unbounded operation                                       |
| -------------------- | --------------------------------------------------------- |
| `DeflateCodec`       | `InflaterOutputStream` writing to `NonCopyingByteArrayOutputStream` |
| `ZstandardCodec`     | `InputStream.transferTo(baos)` with no limit              |
| `BZip2Codec`         | Read loop into `NonCopyingByteArrayOutputStream`          |
| `SnappyCodec`        | Same unbounded pattern                                    |
| `XZCodec`            | Same unbounded pattern                                    |

Any downstream code that calls `DataFileReader.hasNext()` /
`DataFileReader.next()` triggers decompression, including:

- The `avro-tools` CLI (`tojson`, `cat`, `count`, `getmeta`, `concat`, ...)
- Any application using `DataFileReader` or `DataFileStream` to read
  untrusted Avro files
- Streaming data pipelines (Kafka Connect Avro converters, Spark, Flink, ...)

---

## Technical root cause

When Avro reads a data block from an `.avro` file, it calls the codec's
`decompress()` method. For the Deflate codec the code looks like this
(`DeflateCodec.java:83` on the `main` branch):

```java
@Override
public ByteBuffer decompress(ByteBuffer data) throws IOException {
    NonCopyingByteArrayOutputStream baos =
        new NonCopyingByteArrayOutputStream(DEFAULT_BUFFER_SIZE);
    try (OutputStream outputStream = new InflaterOutputStream(baos, getInflater())) {
        // Writes ALL decompressed bytes -- no size check
        outputStream.write(data.array(), computeOffset(data), data.remaining());
    }
    return baos.asByteBuffer();
}
```

There is **no upper bound** on how large `baos` can grow. An attacker only
needs to produce a valid deflate stream whose decompressed output exceeds
available heap memory. Because zeros compress at roughly 1000:1 with deflate
level 9, a 50 KB file is enough to produce 50 MB of output, which is
sufficient to crash a JVM running with `-Xmx32m` and will consume
significant memory on any JVM.

The same pattern exists in every other codec. The Zstandard codec is even
simpler:

```java
try (InputStream ios = ZstandardLoader.input(bytesIn, useBufferPool)) {
    ios.transferTo(baos);   // unbounded
}
```

---

## Multi-codec proof

The PoC now supports all five Avro compression codecs. Each was tested with
a 50 MB decompression bomb (repeating `0xDEADBEEF` pattern) and confirmed
vulnerable:

| Codec | File on disk | Decompressed | Ratio | OOM crash point | Trigger heap |
| ----- | ----------- | ------------ | ----- | --------------- | ------------ |
| **Deflate** | 54 KB | 50 MB | 946:1 | `DeflateCodec.decompress:83` | `-Xmx32m` |
| **BZip2** | 8 KB | 50 MB | 5,913:1 | `BZip2Codec.decompress:69` | `-Xmx32m` |
| **Zstandard** | 6 KB | 50 MB | 8,220:1 | `ZstandardCodec.decompress:85` | `-Xmx32m` |
| **XZ** | 9 KB | 50 MB | 5,628:1 | `XZCodec.decompress:75` | `-Xmx32m` |
| **Snappy** | 2.4 MB | 50 MB | 21:1 | `SnappyCodec.decompress:69` | `-Xmx48m` |

Snappy achieves a lower compression ratio because it prioritizes speed over
compression density, but the vulnerability mechanism is identical: unbounded
decompression with no size limit.

### Generating bombs with different codecs

```bash
# Deflate (default)
java -Xmx256m -cp <jar> poc.CraftBomb bomb-deflate.avro 50 deflate

# BZip2 -- best ratio, smallest file on disk
java -Xmx256m -cp <jar> poc.CraftBomb bomb-bzip2.avro 50 bzip2

# Zstandard -- best ratio overall
java -Xmx256m -cp <jar> poc.CraftBomb bomb-zstandard.avro 50 zstandard

# XZ
java -Xmx256m -cp <jar> poc.CraftBomb bomb-xz.avro 50 xz

# Snappy -- lower ratio but still exploitable
java -Xmx256m -cp <jar> poc.CraftBomb bomb-snappy.avro 50 snappy
```

### Testing all codecs at once

```bash
./run-all-codecs.sh
```

This script generates a bomb for each codec, attempts to read it with a
constrained heap, and reports a summary of which codecs triggered OOM.

---

## The crafted `.avro` file

The PoC includes `CraftBomb.java`, which generates a file specifically
designed to **evade casual inspection** while still triggering the
vulnerability. This is what makes it a realistic attack vector rather than a
synthetic test case.

### Anatomy of the crafted file

```
crafted-bomb.avro (50 KB on disk)
|
|-- Header
|     Schema:    com.example.events.AuditEvent
|     Codec:     deflate
|     Fields:    timestamp (long), user_id (string), event_type (enum),
|                source_ip (string), message (string), attachment (bytes)
|
|-- Block 0  (preamble -- small, decompresses safely)
|     Record #1: alice@example.com   LOGIN     "User authenticated via SSO"
|     Record #2: bob@corp.internal   UPLOAD    "Uploaded quarterly-report-Q4.pdf"  [15-byte PDF stub]
|     Record #3: charlie@example.com DOWNLOAD  "Downloaded dataset export-2025-01-14.csv"
|     Record #4: diana@example.com   DELETE    "Deleted stale cache objects (batch #4091)"
|     Record #5: eve@partner.co      EXPORT    "Exported compliance report CR-2025-0114"
|     Record #6: frank@example.com   LOGIN     "User authenticated via LDAP"
|     Record #7: grace@corp.internal UPLOAD    "Uploaded signed-contract-vendor-A.pdf"   [15-byte PDF stub]
|     Record #8: heidi@example.com   LOGOUT    "Session expired after 30 min idle timeout"
|
|-- Block 1  (bomb -- 50 KB compressed, 50 MB decompressed)
|     Record #9: svc-data-export@internal  EXPORT
|                "Bulk export: full database snapshot for DR replication"
|                attachment = 50 MB of repeating 0xDEADBEEF
```

### Why this is effective

| Property | Detail |
| -------- | ------ |
| **Realistic schema** | Looks like a standard audit/event log. Schema validation passes. |
| **Innocent preamble** | 8 records with plausible users, IPs, timestamps, and actions. Any `--head N` inspection sees only normal data. |
| **Plausible bomb record** | The bomb record is an `EXPORT` event from a service account (`svc-data-export@internal`) with a "database snapshot" attachment -- a scenario that legitimately produces large binary payloads. |
| **Non-zero payload** | The bomb uses repeating `0xDEADBEEF` instead of all-zeros, bypassing naive "check for zero-filled data" heuristics while still achieving ~1005:1 compression. |
| **Block-separated** | Preamble records are flushed into their own Avro sync block. The bomb occupies a separate block. The reader **must** decompress the bomb block to check for more records (`hasNext()`), so the OOM is unavoidable. |
| **Tiny on disk** | 50 KB total -- small enough to embed in an email, upload via REST API, or drop into an S3 bucket unnoticed. |

### Metrics

| Metric | Value |
| ------ | ----- |
| File size on disk | **52,174 bytes (50 KB)** |
| Total records | **9** (8 normal + 1 bomb) |
| Bomb payload (uncompressed) | **50 MB** (52,428,800 bytes) |
| Bomb pattern | Repeating `0xDEADBEEF` |
| Compression ratio | **~1005:1** |
| Heap required to crash | **< 50 MB** (`-Xmx32m` reliably triggers OOM) |

---

## How the PoC works

The PoC consists of three programs:

### `CraftBomb.java` (recommended)

1. Defines a realistic `AuditEvent` schema with six fields including a
   `bytes` attachment.
2. Writes 8 innocent preamble records with plausible field values.
3. Flushes a sync block boundary so the preamble sits in its own block.
4. Writes a 9th record carrying 50 MB of repeating `0xDEADBEEF` in the
   attachment field, compressed with deflate level 9.
5. The resulting file is ~50 KB on disk.

### `CreatePoC.java` (minimal variant)

1. Defines a minimal schema with a single `bytes` field.
2. Writes one record containing 50 MB of zeros.
3. The resulting file is ~49 KB. This is the simplest possible reproduction.

### `TriggerOOM.java`

1. Opens any `.avro` file with a standard `DataFileReader`.
2. Prints the schema and codec metadata.
3. Iterates through records, printing a one-line summary of each.
4. When the bomb block is decompressed, the JVM runs out of memory.
5. Catches `OutOfMemoryError`, prints a confirmation with the full stack
   trace, and exits with code **99**.

---

## Quick start -- Docker

This is the recommended way to reproduce the vulnerability in an isolated
environment.

```bash
# Build the image (multi-stage: Maven build + Alpine JRE runtime)
docker build -t avro-oom-poc .

# Run with a container memory limit
docker run --rm --memory=512m avro-oom-poc
```

The container will:

1. Generate `crafted-bomb.avro` (step 1, runs with `-Xmx256m`)
2. Read the first 8 records successfully (step 2, runs with `-Xmx32m`)
3. Crash with `OutOfMemoryError` on the 9th record's block
4. Print `VULNERABILITY CONFIRMED` and exit with code **99**

The Dockerfile uses a **multi-stage build**:

- **Stage 1** (`maven:3.9-eclipse-temurin-17`): compiles the project into a
  shaded uber-jar.
- **Stage 2** (`eclipse-temurin:17-jre-alpine`): minimal ~80 MB runtime image
  that only contains the JRE and the uber-jar.

---

## Quick start -- local Maven

Requirements: JDK 11+ and Maven 3.6+.

```bash
# One-step: build + generate + trigger
./run-poc.sh
```

Or manually:

```bash
# 1. Build
mvn package -DskipTests

# 2. Generate the crafted bomb file (needs large heap to hold 50 MB in memory)
java -Xmx256m -cp target/avro-decompression-bomb-poc-1.0-SNAPSHOT.jar \
    poc.CraftBomb crafted-bomb.avro

# 3. Trigger OOM (32 MB heap cannot hold 50 MB decompressed block)
java -Xmx32m -cp target/avro-decompression-bomb-poc-1.0-SNAPSHOT.jar \
    poc.TriggerOOM crafted-bomb.avro
```

You can also use the minimal variant:

```bash
java -Xmx256m -cp target/avro-decompression-bomb-poc-1.0-SNAPSHOT.jar \
    poc.CreatePoC poc.avro

java -Xmx32m -cp target/avro-decompression-bomb-poc-1.0-SNAPSHOT.jar \
    poc.TriggerOOM poc.avro
```

---

## Expected output

```
=== Avro Decompression Bomb -- Crafted File Generator ===

Output:              crafted-bomb.avro
Schema:              com.example.events.AuditEvent
Preamble records:    8
Bomb payload:        50 MB (repeating 0xDEADBEEF)

Result:
  Total records:     9 (8 normal + 1 bomb)
  File size on disk: 52174 bytes (50 KB)
  Decompressed bomb: 50 MB
  Compression ratio: 1005:1

=== Avro Decompression Bomb PoC - OOM Trigger ===

Reading file: crafted-bomb.avro
Max heap:     32 MB

File size on disk: 52174 bytes (50 KB)

Schema: com.example.events.AuditEvent
Codec:  deflate

Reading records...

  #1 {timestamp=1736899200000, user_id=alice@example.com, event_type=LOGIN, ...}
  #2 {timestamp=1736899201500, user_id=bob@corp.internal, event_type=UPLOAD, ...}
  #3 {timestamp=1736899203000, user_id=charlie@example.com, event_type=DOWNLOAD, ...}
  #4 {timestamp=1736899210000, user_id=diana@example.com, event_type=DELETE, ...}
  #5 {timestamp=1736899215000, user_id=eve@partner.co, event_type=EXPORT, ...}
  #6 {timestamp=1736899220000, user_id=frank@example.com, event_type=LOGIN, ...}
  #7 {timestamp=1736899225000, user_id=grace@corp.internal, event_type=UPLOAD, ...}
  #8 {timestamp=1736899230000, user_id=heidi@example.com, event_type=LOGOUT, ...}

*** VULNERABILITY CONFIRMED ***

OutOfMemoryError triggered during Avro decompression!
Error: Java heap space

Stack trace:
java.lang.OutOfMemoryError: Java heap space
    at java.base/java.util.Arrays.copyOf(Arrays.java:3537)
    at java.base/java.io.ByteArrayOutputStream.ensureCapacity(ByteArrayOutputStream.java:100)
    at java.base/java.io.ByteArrayOutputStream.write(ByteArrayOutputStream.java:132)
    at java.base/java.util.zip.InflaterOutputStream.write(InflaterOutputStream.java:278)
    at org.apache.avro.file.DeflateCodec.decompress(DeflateCodec.java:83)
    at org.apache.avro.file.DataFileStream$DataBlock.decompressUsing(DataFileStream.java:394)
    at org.apache.avro.file.DataFileStream.hasNext(DataFileStream.java:227)
    at poc.TriggerOOM.main(TriggerOOM.java:54)
```

Exit code: **99** (vulnerability confirmed).

---

## PR #3625 analysis

[PR #3625](https://github.com/apache/avro/pull/3625) proposes a fix for this
vulnerability, but **only patches `DeflateCodec.java`**. The four other
vulnerable codecs are not addressed.

### What the PR does

The PR modifies `DeflateCodec.decompress()` to:

1. Use `Inflater.inflate()` in a chunked loop instead of
   `InflaterOutputStream.write()`.
2. Track total decompressed bytes.
3. Throw `AvroRuntimeException` if total exceeds a configurable limit
   (`org.apache.avro.limits.decompress.maxLength`, default 200 MB).

### What the PR does NOT do

| Codec | Patched by PR #3625? | Vulnerable code path |
| ----- | -------------------- | -------------------- |
| Deflate | **Yes** | `InflaterOutputStream` -> bounded loop |
| BZip2 | **No** | `read()` loop into unbounded `NonCopyingByteArrayOutputStream` |
| Zstandard | **No** | `ios.transferTo(baos)` -- completely unbounded |
| Snappy | **No** | `ByteBuffer.allocate(uncompressedSize)` -- size from file, no limit |
| XZ | **No** | `IOUtils.copy()` into unbounded `ByteArrayOutputStream` |

The PR author acknowledged this gap: *"Other codecs have the same issue. We
can discuss the fix for those in follow-up."*

### Implication

Even after PR #3625 is merged, an attacker can simply use a different codec
(BZip2 achieves 5,913:1, Zstandard achieves 8,220:1) to bypass the fix
entirely. The most dangerous codecs from an attacker's perspective
(Zstandard, BZip2, XZ) remain **fully exploitable**.

This PoC proves this by generating and crashing bomb files for all five
codecs -- see [Multi-codec proof](#multi-codec-proof).

---

## Project structure

```
avro-oom-compression-poc/
|-- Dockerfile                          # Multi-stage Docker build + run
|-- pom.xml                             # Maven project (Avro 1.12.0, shaded jar)
|-- run-poc.sh                          # Local build-and-run helper (Deflate only)
|-- run-all-codecs.sh                   # Multi-codec proof script (all 5 codecs)
|-- src/
|   `-- main/
|       `-- java/
|           `-- poc/
|               |-- CraftBomb.java      # Generates realistic bomb file (any codec)
|               |-- CreatePoC.java      # Generates the minimal 49 KB bomb file
|               `-- TriggerOOM.java     # Reads any .avro file, triggers OOM
`-- README.md                           # This file
```

### Key files

| File | Purpose |
| ---- | ------- |
| `pom.xml` | Maven build with `maven-shade-plugin` to produce a single uber-jar containing Avro 1.12.0 and all codec dependencies (Zstandard, Snappy, XZ, Commons Compress). Targets Java 11. |
| `CraftBomb.java` | Generates a realistic audit-event `.avro` file with 8 innocent preamble records and bomb records carrying repeating `0xDEADBEEF` in the `attachment` field. Supports all codecs via CLI argument: `java poc.CraftBomb [output] [size-MB] [codec]`. |
| `CreatePoC.java` | Minimal variant: writes one record with 50 MB of zeros in a single `bytes` field. Simpler but obviously synthetic. |
| `TriggerOOM.java` | Opens any `.avro` file with `DataFileReader`, prints schema/codec metadata and a one-line summary per record, then crashes with OOM on the bomb block. Exits with code 99 on success. |
| `run-poc.sh` | Shell script that builds (if needed), generates a Deflate bomb, and runs the trigger with `-Xmx32m`. |
| `run-all-codecs.sh` | Shell script that tests all 5 codecs (Deflate, BZip2, Zstandard, Snappy, XZ), generating and triggering a bomb for each. Reports a summary showing all codecs are vulnerable. |
| `Dockerfile` | Two-stage build: stage 1 compiles with Maven, stage 2 copies the jar into an Alpine JRE image and runs both steps via an embedded entrypoint script. |

---

## Prerequisites

### Local execution

- **JDK** 11 or later
- **Maven** 3.6 or later

### Docker execution

- **Docker** 20.10 or later (BuildKit support for the `COPY <<` heredoc syntax
  requires Docker 23+; tested with Docker 29.4)

---

## Impact assessment

| Aspect | Detail |
| ------ | ------ |
| **Confidentiality** | None -- this is a DoS, not an information leak. |
| **Integrity** | None -- no data is modified. |
| **Availability** | **High** -- the JVM crashes with `OutOfMemoryError`, terminating the process. In a shared environment, this can affect co-located services. |
| **Attack complexity** | **Low** -- the attacker only needs to supply a valid `.avro` file. No authentication or special privileges are required. |
| **Exploitability** | **Trivial** -- the bomb file is 50 KB and can be generated with standard Avro APIs. No binary manipulation is needed. |
| **Blast radius** | Any Java application that reads untrusted Avro files: data pipelines, REST APIs, CLI tools (`avro-tools`), streaming consumers. |

### Real-world attack scenarios

1. **Data pipeline poisoning**: An attacker uploads a bomb `.avro` file to a
   shared data lake (S3, HDFS, GCS). Any Spark/Flink/Beam job that reads this
   file crashes its executor JVMs.

2. **API abuse**: A service that accepts Avro-encoded payloads (e.g. Schema
   Registry, Confluent REST Proxy) can be crashed by posting a small request
   body.

3. **CLI tool crash**: Running `avro-tools tojson crafted-bomb.avro` crashes
   immediately, which is a problem for CI/CD validation steps or admin scripts.

4. **Supply chain**: A compromised upstream data producer writes bomb records
   into a shared Avro topic. All downstream consumers crash when they reach
   the poisoned offset.

---

## Suggested mitigation

The fix proposed in [PR #3625](https://github.com/apache/avro/pull/3625)
adds a configurable maximum decompression size **but only for Deflate**.
See [PR #3625 analysis](#pr-3625-analysis) for details on the coverage gap.

A complete fix would need to:

1. Add a system property `org.apache.avro.limits.decompress.maxLength`
   (default: 200 MB) -- already done in PR #3625.
2. Apply size-bounded decompression to **all five codecs**: Deflate, BZip2,
   Zstandard, Snappy, and XZ -- only Deflate is currently patched.
3. In each codec's `decompress()`, track total bytes written and throw
   `AvroRuntimeException` if the limit is exceeded.

Until a complete fix is released, possible workarounds include:

- **Restrict file sources**: Only read Avro files from trusted origins.
- **Set aggressive `-Xmx`**: This limits damage but still crashes the reader
  process.
- **Validate file size before reading**: Check that the compressed data block
  size and declared record count are within reasonable bounds (this requires
  custom code wrapping `DataFileReader`).

---

## References

- [Apache Avro PR #3625 -- Add decompression size limit](https://github.com/apache/avro/pull/3625)
- [CWE-409: Improper Handling of Highly Compressed Data (Decompression Bomb)](https://cwe.mitre.org/data/definitions/409.html)
- [OWASP: Denial of Service via Decompression Bomb](https://owasp.org/www-community/vulnerabilities/Decompression_Bombs)
- [Apache Avro Java source: DeflateCodec.java](https://github.com/apache/avro/blob/main/lang/java/avro/src/main/java/org/apache/avro/file/DeflateCodec.java)
- [Apache Avro Java source: ZstandardCodec.java](https://github.com/apache/avro/blob/main/lang/java/avro/src/main/java/org/apache/avro/file/ZstandardCodec.java)
- [Apache Avro Java source: BZip2Codec.java](https://github.com/apache/avro/blob/main/lang/java/avro/src/main/java/org/apache/avro/file/BZip2Codec.java)
