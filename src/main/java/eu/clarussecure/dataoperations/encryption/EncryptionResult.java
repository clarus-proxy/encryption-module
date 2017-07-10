package eu.clarussecure.dataoperations.encryption;

import eu.clarussecure.dataoperations.DataOperationResult;

public class EncryptionResult extends DataOperationResult {
    private String[][] decryptedContent;
    private String[] decryptedAttributeNames;

    public EncryptionResult(String[] attributeNames, String[][] content) {
        this.decryptedAttributeNames = attributeNames;
        this.decryptedContent = content;
    }

    public String[][] getDecryptedContent() {
        return this.decryptedContent;
    }

    public String[] getDecryptedAttributeNames() {
        return this.decryptedAttributeNames;
    }
}
