package eu.clarussecure.dataoperations.encryption;

public class KeyStore {
    public KeyStore() {
        // Nothing to do here
    }

    public String retrieveKey(String dataID) {
        // TODO - Implement the connection to the DB here
        String key;
        
        return "Foo98765Lal12345"; // 16 chars * 8 bits = 128 bits cipher
    }

    public String retrieveInitVector(String dataID) {
        // TODO - Implement the connection to the DB here
        // TODO - Implement the generatio of Random Init Vectors
        return "RandomInitVector"; // Random 16 bytes Init Vector
    }
}
