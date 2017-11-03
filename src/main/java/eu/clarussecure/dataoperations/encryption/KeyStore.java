package eu.clarussecure.dataoperations.encryption;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.MongoDatabase;
import static com.mongodb.client.model.Filters.eq;
import com.mongodb.client.model.UpdateOptions;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bson.Document;

public class KeyStore {
    private static KeyStore instance = null;
    private final MongoDatabase db;
    private final MongoClient mongoClient;
    private final MongoCollection<Document> keystoreCollection;
    private int instancesNumber;

    private String confFile = "/etc/clarus/clarus-keystore.conf";
    private String mongoDBHostname = "localhost"; // Default server
    private int mongoDBPort = 27017; // Default port
    private String clarusDBName = "CLARUS"; // Default DB name

    private KeyStore() {
        // Identify the platform to correctly locate the configuration File
        if(System.getProperty("os.name").toLowerCase().contains("windows")){
            // This is a Windows Platform. Use a Windows-friendly path
            confFile = "C:" + File.pathSeparator + "CLARUS" + File.pathSeparator + "clarus-keystore.conf";
        } else {
            // Since CLARUS does not support machines except for Windows, Linux
            // and Mac, in this case we will assume this is a Linux Machine.
            confFile = "/etc/clarus/clarus-keystore.conf";
        }
        // Initiate the basic connections to the database
        // Correctly configure the log level
        Logger mongoLogger = Logger.getLogger("org.mongodb.driver");
        mongoLogger.setLevel(Level.SEVERE);
        // Open the configuraiton file to extract the information from it.
        this.processConfigurationFile();
        // Create a new client connecting to "localhost" on port 
        this.mongoClient = new MongoClient(this.mongoDBHostname, this.mongoDBPort);

        // Get the database (will be created if not present)
        this.db = mongoClient.getDatabase(this.clarusDBName);
        this.keystoreCollection = this.db.getCollection("keystore");

        this.instancesNumber++;
    }

    public static KeyStore getInstance() {
        if (KeyStore.instance == null) {
            KeyStore.instance = new KeyStore();
        }
        return KeyStore.instance;
    }

    public void deleteInstance() {
        this.instancesNumber--;

        if (this.instancesNumber <= 0) {
            this.mongoClient.close();
            KeyStore.instance = null;
        }
    }

    public SecretKey retrieveKey(String dataID) {
        SecretKey key = null;
        String stringKey;
        // Check if there is an entry for this data ID
        if (this.keystoreCollection.count(eq("dataID", dataID)) <= 0) {
            // There is not a Key-IV pair, generate one
            this.generateSecurityParameters(dataID);
        }

        // At this point, a Key-IV pair EXISTS in the DB for this dataID
        // Retrieve the key
        MongoCursor<Document> keys = this.keystoreCollection.find(eq("dataID", dataID)).iterator();
        if (keys.hasNext()) {
            // A key was found, retrieve it
            Document doc = keys.next();
            stringKey = doc.getString("enckey");
            // Create the Key Object
            byte[] bytesKey = Base64.getDecoder().decode(stringKey);
            key = new SecretKeySpec(bytesKey, 0, bytesKey.length, "AES");
        }
        return key;
    }

    public byte[] retrieveInitVector(String dataID) {
        byte[] bytesIV = new byte[16];
        // Check if there is an entry for this data ID
        if (this.keystoreCollection.count(eq("dataID", dataID)) <= 0) {
            // There is not a Key-IV pair, generate one
            this.generateSecurityParameters(dataID);
        }

        // At this point, a Key-IV pair EXISTS in the DB for this dataID
        // Retrieve the IV
        MongoCursor<Document> ivs = this.keystoreCollection.find(eq("dataID", dataID)).iterator();
        if (ivs.hasNext()) {
            // An IV was found, retrieve it
            Document doc = ivs.next();
            String stringIV = doc.getString("initvector");
            // Decode the IV from the string
            bytesIV = Base64.getDecoder().decode(stringIV);
        }

        return bytesIV;
    }

    protected boolean generateSecurityParameters(String dataID) {
        SecretKey key = null;
        String stringKey;
        byte[] bytesIV = new byte[16];
        String stringIV;
        try {
            // Generate new Key for AES algorithm
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(this.getKeyLength());
            key = keygen.generateKey();

            // Encode it into a String
            stringKey = Base64.getEncoder().encodeToString(key.getEncoded());

            // Generate a Random Init Vector
            SecureRandom randomGen = new SecureRandom();
            randomGen.nextBytes(bytesIV);

            // Encode it into a String
            stringIV = Base64.getEncoder().encodeToString(bytesIV);

            // Prepare the document into the dabase
            Document doc = new Document("dataID", dataID);
            doc.append("enckey", stringKey);
            doc.append("initvector", stringIV);

            // Store the encoded key into the database
            boolean ack = this.keystoreCollection
                    .replaceOne(eq("dataID", dataID), doc, new UpdateOptions().upsert(true)).wasAcknowledged();
            return ack;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return false;
    }

    private int getKeyLength() {
        // This method should retrieve the key length (in bits) from the DB
        MongoCursor<Document> cursor = this.keystoreCollection.find(eq("conf", "simple-keylength")).iterator();

        int keyLength = 128; // Default value is 128 bits
        while (cursor.hasNext()) {
            keyLength = cursor.next().getDouble("keylength").intValue();
        }
        return keyLength;
    }

    private void processConfigurationFile() throws RuntimeException {
        // Open the file in read-only mode. This will avoid any permission problem
        try {
            // Read all the lines and join them in a single string
            List<String> lines = Files.readAllLines(Paths.get(this.confFile));
            String content = lines.stream().reduce("", (a, b) -> a + b);

            // Use the bson document parser to extract the info
            Document doc = Document.parse(content);
            this.mongoDBHostname = doc.getString("CLARUS_keystore_db_hostname");
            this.mongoDBPort = doc.getInteger("CLARUS_keystore_db_port");
            this.clarusDBName = doc.getString("CLARUS_keystore_db_name");
        } catch (IOException e) {
            throw new RuntimeException("CLARUS configuration file could not be processed", e);
        }
    }
}
