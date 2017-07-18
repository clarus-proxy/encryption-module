package eu.clarussecure.dataoperations.encryption;

import eu.clarussecure.dataoperations.Criteria;
import eu.clarussecure.dataoperations.DataOperationCommand;
import java.util.Map;

public class EncryptionCommand extends DataOperationCommand {

    public EncryptionCommand(String[] attributeNames, String[] protectedAttributeNames, String[][] protectedContents,
            Map<String, String> mapping, Criteria[] criteria) {
        this.protectedAttributeNames = protectedAttributeNames;
        this.attributeNames = attributeNames;
        this.extraBinaryContent = null;
        this.extraProtectedAttributeNames = null;
        this.protectedContents = protectedContents;
        this.mapping = mapping;
        this.criteria = criteria;
    }

    public void setCriteria(Criteria[] criteria) {
        this.criteria = criteria;
    }
}
