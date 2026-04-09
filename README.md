# Avro Decompression Bomb PoC (CWE-409)

Proof of concept demonstrating a **decompression bomb** vulnerability in
[Apache Avro](https://github.com/apache/avro)'s Java codec layer.

A crafted Avro file that is **49 KB on disk** decompresses to **50 MB** at
read time, causing `java.lang.OutOfMemoryError` and crashing the JVM. The
root cause is that every compression codec in Avro decompresses into an
**unbounded `ByteArrayOutputStream`** with no size limit.

> **Upstream PR:** <https://github.com/apache/avro/pull/3625>

---

## Table of contents

1. [Vulnerability summary](#vulnerability-summary)
2. [Affected versions and components](#affected-versions-and-components)
3. [Technical root cause](#technical-root-cause)
4. [How the PoC works](#how-the-poc-works)
5. [Quick start -- Docker](#quick-start----docker)
6. [Quick start -- local Maven](#quick-start----local-maven)
7. [Expected output](#expected-output)
8. [Project structure](#project-structure)
9. [Prerequisites](#prerequisites)
10. [Impact assessment](#impact-assessment)
11. [Suggested mitigation](#suggested-mitigation)
12. [References](#references)

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
level 9, a 49 KB file is enough to produce 50 MB of output, which is
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

## How the PoC works

The PoC consists of two programs:

### Step 1 -- `CreatePoC.java`

1. Defines a minimal Avro schema with a single `bytes` field.
2. Opens a `DataFileWriter` with **deflate level 9** (maximum compression).
3. Writes a single record containing **50 MB of zeros**.
4. The resulting `poc.avro` file is ~49 KB on disk (compression ratio ~1026:1).

### Step 2 -- `TriggerOOM.java`

1. Opens the `poc.avro` file with a standard `DataFileReader`.
2. Calls `reader.hasNext()`, which internally calls `DeflateCodec.decompress()`.
3. The codec tries to inflate the 49 KB compressed block into 50 MB.
4. With `-Xmx32m`, the JVM cannot allocate 50 MB and throws
   `OutOfMemoryError`.
5. The program catches the `OutOfMemoryError`, prints a confirmation message
   with the full stack trace, and exits with code **99**.

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

1. Generate `poc.avro` (step 1, runs with `-Xmx256m`)
2. Attempt to read it (step 2, runs with `-Xmx32m`)
3. Print `VULNERABILITY CONFIRMED` and exit with code **99**

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

# 2. Generate the malicious Avro file (needs large heap to hold 50MB in memory)
java -Xmx256m -cp target/avro-decompression-bomb-poc-1.0-SNAPSHOT.jar \
    poc.CreatePoC poc.avro

# 3. Trigger OOM (32 MB heap cannot hold 50 MB decompressed output)
java -Xmx32m -cp target/avro-decompression-bomb-poc-1.0-SNAPSHOT.jar \
    poc.TriggerOOM poc.avro
```

---

## Expected output

```
=== Avro Decompression Bomb PoC - File Generator ===

Creating malicious Avro file: poc.avro
Payload size (uncompressed): 50 MB

Result:
  File size on disk: 51125 bytes (49 KB)
  Decompressed size: 50 MB
  Compression ratio: 1026:1

=== Avro Decompression Bomb PoC - OOM Trigger ===

Reading file: poc.avro
Max heap:     32 MB
File size on disk: 51125 bytes (49 KB)

Attempting to read and decompress...

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

Root cause: DeflateCodec.decompress() decompresses into an
unbounded ByteArrayOutputStream with no size limit, allowing
a small compressed payload to expand until OOM.

CWE-409: Improper Handling of Highly Compressed Data
Impact: Denial of Service (DoS) - JVM crash via OOM
```

Exit code: **99** (vulnerability confirmed).

---

## Project structure

```
avro-oom-compression-poc/
|-- Dockerfile                          # Multi-stage Docker build + run
|-- pom.xml                             # Maven project (Avro 1.12.0, shaded jar)
|-- run-poc.sh                          # Local build-and-run helper script
|-- src/
|   `-- main/
|       `-- java/
|           `-- poc/
|               |-- CreatePoC.java      # Generates the 49 KB bomb file
|               `-- TriggerOOM.java     # Reads it, triggers OOM
`-- README.md                           # This file
```

### Key files

| File | Purpose |
| ---- | ------- |
| `pom.xml` | Maven build with `maven-shade-plugin` to produce a single uber-jar containing Avro 1.12.0 and all transitive dependencies (Jackson, Commons Compress, etc.). Targets Java 11. |
| `CreatePoC.java` | Writes a valid Avro data file with a single record containing 50 MB of zeros, compressed with deflate level 9. The result is ~49 KB. |
| `TriggerOOM.java` | Opens the file with `DataFileReader` and iterates. Catches `OutOfMemoryError` explicitly, prints the stack trace, and exits with code 99. |
| `run-poc.sh` | Shell script that builds (if needed), generates `poc.avro`, and runs the trigger with `-Xmx32m`. Interprets exit codes. |
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
| **Exploitability** | **Trivial** -- the bomb file is 49 KB and can be generated with standard Avro APIs. No binary manipulation is needed. |
| **Blast radius** | Any Java application that reads untrusted Avro files: data pipelines, REST APIs, CLI tools (`avro-tools`), streaming consumers. |

### Real-world attack scenarios

1. **Data pipeline poisoning**: An attacker uploads a bomb `.avro` file to a
   shared data lake (S3, HDFS, GCS). Any Spark/Flink/Beam job that reads this
   file crashes its executor JVMs.

2. **API abuse**: A service that accepts Avro-encoded payloads (e.g. Schema
   Registry, Confluent REST Proxy) can be crashed by posting a small request
   body.

3. **CLI tool crash**: Running `avro-tools tojson poc.avro` crashes
   immediately, which is a problem for CI/CD validation steps or admin scripts.

---

## Suggested mitigation

The fix proposed in [PR #3625](https://github.com/apache/avro/pull/3625)
adds a configurable maximum decompression size. The approach is:

1. Add a system property `org.apache.avro.limits.decompress.maxLength`
   (default: 200 MB).
2. In `DeflateCodec.decompress()`, decompress in chunks using
   `Inflater.inflate()` directly, tracking total bytes written.
3. If the total exceeds the limit, throw `AvroRuntimeException` instead of
   letting the JVM run out of memory.
4. Apply the same pattern to all other codecs.

Until a fix is released, possible workarounds include:

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
