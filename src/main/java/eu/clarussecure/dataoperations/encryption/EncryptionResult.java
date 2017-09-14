package eu.clarussecure.dataoperations.encryption;

import java.util.Random;

import eu.clarussecure.dataoperations.DataOperationResponse;

public class EncryptionResult extends DataOperationResponse {

    public EncryptionResult(String[] attributeNames, String[][] contents) {
        super.id = new Random().nextInt();
        super.attributeNames = attributeNames; // headers originales
        super.contents = contents;
    }

    public String[][] getDecryptedContent() {
        return this.contents;
    }

    public String[] getDecryptedAttributeNames() {
        return this.attributeNames;
    }
}
