package eu.clarussecure.dataoperations.encryption;

import eu.clarussecure.dataoperations.AttributeNamesUtilities;
import eu.clarussecure.dataoperations.Criteria;
import eu.clarussecure.dataoperations.DataOperation;
import eu.clarussecure.dataoperations.DataOperationCommand;
import eu.clarussecure.dataoperations.DataOperationResult;
import eu.clarussecure.dataoperations.encryption.operators.Select;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class EncryptionModule implements DataOperation {

    // Data extracted from the security policy
    protected Map<String, String> attributeTypes = new HashMap<>(); // qualifName->type
    protected Map<String, String> typesProtection = new HashMap<>(); // type->protectionModule
    protected Map<String, String> typesDataIDs = new HashMap<>(); // type->idKey
    protected KeyStore keyStore = KeyStore.getInstance();

    // Map of the fully-qualified Attribute Names
    protected List<String> qualifiedAttributes = new ArrayList<>();

    // Mapping to determine where to store each qualified name
    protected int cloudsNumber;
    protected Map<String, Integer> attributeClouds = new HashMap<>();

    // Map between plain and encrypted attribute Names
    protected Map<String, String> attributesMapping = new HashMap<>();

    public EncryptionModule(Document policy) {
        // TODO - Extract the number of "endpoints" (aka Clouds) from the policy.
        // At this point this number WILL BE HARD CODED!!!
        this.cloudsNumber = 1;

        // First, get the types of each attribute and build the map
        NodeList nodes = policy.getElementsByTagName("attribute");
        List<String> attributeNames = new ArrayList<>();
        for (int i = 0; i < nodes.getLength(); i++) {
            // Get the node and the list of its attributes
            Node node = nodes.item(i);
            NamedNodeMap attributes = node.getAttributes();
            // Extract the required attributes
            String attributeName = attributes.getNamedItem("name").getNodeValue();
            String attributeType = attributes.getNamedItem("attribute_type").getNodeValue();
            // Add the information to the map
            this.attributeTypes.put(attributeName, attributeType);
            // Store the attribute names to fully qualify them
            attributeNames.add(attributeName);
        }

        // Fully qualify the attribute Names
        this.qualifiedAttributes = AttributeNamesUtilities.fullyQualified(attributeNames);

        // Replace the keys of the attributeTypes Map
        this.attributeTypes = this.attributeTypes.keySet().stream() // Iterate over the keys of the original map 
                .collect(Collectors.toMap( // Collect them in a new map 
                        // The new key is the single one that in qualifiedAttributes such that the original key is suffix of the qualified one
                        // (i.e. filter the qAttrs such that the qAttr ends with the original name)
                        key -> this.qualifiedAttributes.stream().filter(k -> k.endsWith(key)).findAny().orElse(null),
                        // The new value is the same of the original mapping
                        key -> this.attributeTypes.get(key)));

        // Second , get the protection of each attribute type and their idKeys
        nodes = policy.getElementsByTagName("attribute_type");
        for (int i = 0; i < nodes.getLength(); i++) {
            // Get the node and the list of its attributes
            Node node = nodes.item(i);
            NamedNodeMap attributes = node.getAttributes();
            // Extract the reuqired attributes
            String attributeType = attributes.getNamedItem("type").getNodeValue();
            String typeProtection = attributes.getNamedItem("protection").getNodeValue();
            // Add the information to the map
            this.typesProtection.put(attributeType, typeProtection);
            // Get the idKey only if the protection module is "encryption" or "simple"
            if (typeProtection.equals("encryption") || typeProtection.equals("simple")) {
                String dataID = attributes.getNamedItem("id_key").getNodeValue();
                this.typesDataIDs.put(attributeType, dataID);
            }
        }
        // FIXME - Should the policy specify in which cloud to store the encrypted data?
        // If so, this information should be available in the "attribute_type" tag
        // so the "mapping" showing where to store each attribute should be built here.
        /* Example:
         * <endpoint id=1 protocol="prot" port="12345">
         *   <parameters>
         *      <parameter param="name1" value="val1" />
         *   </parameters>
         * </endpoint>
         * <endpoint id=2 protocol="prot1" port="98765">
         *   <parameters>
         *      <parameter param="name3" value="val12" />
         *   </parameters>
         * </endpoint>
         * ...
         * <attribute_type
         *   type="confidential"
         *   protection="encryption"
         *   id_key="176"
         *   cloud="1">
         */
        // At the moment, the mapping will be done assuming the encrypted attributes go to the first cloud
        this.qualifiedAttributes.forEach(qualifiedName -> this.attributeClouds.put(qualifiedName, 0));

        // Generate the map between qualified Attributes and protected Attributes Names
        this.attributesMapping = this.qualifiedAttributes.stream() // Get all the qualified Names
                .collect(Collectors.toMap( // Reduce them into a new Map
                        key -> key, // Use the same qualified Attribute Name as key
                        key -> { // Generate the mapped values: the "encrypted" ones
                            String attribEnc = null;
                            try {
                                // Obtain the dataID
                                String dataID = this.typesDataIDs.get(this.attributeTypes.get(key));

                                // Encrypt the column name only if the policy says so
                                // Get the prpteciton type of this attribute
                                String protection = this.typesProtection.get(this.attributeTypes.get(key));
                                // Encrypt only if the protection type is "encryption" or "simple"
                                if (protection.equals("encryption") || protection.equals("simple")) {
                                    byte[] bytesAttribEnc;

                                    // Initialize the Secret Key and the Init Vector of the Cipher
                                    IvParameterSpec iv = new IvParameterSpec(this.keyStore.retrieveInitVector(dataID));
                                    SecretKey sk = this.keyStore.retrieveKey(dataID);

                                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                    cipher.init(Cipher.ENCRYPT_MODE, sk, iv);

                                    // NOTE - To correctly encrypt, First cipher, THEN Base64 encode
                                    bytesAttribEnc = cipher.doFinal(key.getBytes());
                                    attribEnc = Base64.getEncoder().encodeToString(bytesAttribEnc);
                                } else {
                                    // Otherwise, just let the attribute name pass in plain text
                                    attribEnc = key;
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                                System.exit(1);
                            }
                            return attribEnc;
                        }));
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        this.keyStore.deleteInstance();
    }

    @Override
    public List<DataOperationCommand> get(String[] attributeNames, Criteria[] criteria) {
        // IMPORTANT REMARK:
        // Since the encryption is not homomorphic, all the data must be retrieved
        // The selection of the rows will be done in the outboud GET, after decrypting the data

        // Generate the ORDERED list of the protected attributeNames
        List<String> protectedAttributes = new ArrayList<>();
        Stream.of(attributeNames)
                .forEach(attributeName -> protectedAttributes.add(this.attributesMapping.get(attributeName)));

        // Third, create the Comman object
        DataOperationCommand command = new EncryptionCommand(attributeNames,
                protectedAttributes.toArray(new String[attributeNames.length]), null, this.attributesMapping, criteria);
        List<DataOperationCommand> commands = new ArrayList<>();
        commands.add(command);
        return commands;
    }

    @Override
    public List<DataOperationResult> get(List<DataOperationCommand> promise, List<String[][]> contents) {
        // Iterate over all the given commands
        List<DataOperationResult> commands = new ArrayList<>();
        int rowCount = 0;
        for (int n = 0; n < promise.size(); n++) {
            DataOperationCommand com = promise.get(n);
            String[][] content = contents.get(n);

            String[] plainAttributeNames = new String[com.getProtectedAttributeNames().length];
            List<String[]> plainContents = new ArrayList<>();
            Map<String, String> mapAttributes = new HashMap<>();

            Base64.Decoder decoder = Base64.getDecoder();

            // First, parse the selection criteria and prepare the Select instances
            Map<String, List<Select>> selectorsSet = new HashMap<>();

            if (com.getCriteria() == null) {
                // There is no criteria, use the Identity Function
                List<Select> selectors = selectorsSet.get("all");
                if (selectors == null) {
                    selectors = new ArrayList<>();
                    selectorsSet.put("all", selectors);
                }
                selectors.add(Select.getInstance("id", "")); // No threshold is required for the identity
            } else {
                // There are criteria. Build the selectors
                for (Criteria crit : com.getCriteria()) {
                    // Get the selectors of the attribute
                    List<Select> selectors = selectorsSet.get(crit.getAttributeName());
                    // Create the list of it does not exist
                    if (selectors == null) {
                        selectors = new ArrayList<>();
                        selectorsSet.put(crit.getAttributeName(), selectors);
                    }
                    // Add the current selector to the list
                    selectors.add(Select.getInstance(crit.getOperator(), crit.getValue()));
                }
            }

            // Second, decipher the attribute names
            try {
                // First, decipher the attribute Names and map them to the origial ones
                for (int i = 0; i < com.getProtectedAttributeNames().length; i++) {
                    // Get the proteciton type of this attribute
                    String protection = this.typesProtection.get(this.attributeTypes.get(com.getAttributeNames()[i]));

                    // Decrypt only if the protection type is "encryption" or "simple"
                    if (protection.equals("encryption") || protection.equals("simple")) {
                        // Obtain the dataID
                        String dataID = this.typesDataIDs.get(this.attributeTypes.get(com.getAttributeNames()[i]));

                        // Initialize the Secret Key and the Init Vector of the Cipher
                        IvParameterSpec iv = new IvParameterSpec(this.keyStore.retrieveInitVector(dataID));
                        SecretKey sk = this.keyStore.retrieveKey(dataID);

                        // Initialize the required instances of Ciphers
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(Cipher.DECRYPT_MODE, sk, iv);
                        // NOTE - To correctly decrypt, first Base64 decode, THEN decipher
                        byte[] bytesEncAttributeName = cipher
                                .doFinal(decoder.decode(com.getProtectedAttributeNames()[i]));
                        plainAttributeNames[i] = new String(bytesEncAttributeName);
                    } else {
                        plainAttributeNames[i] = com.getProtectedAttributeNames()[i];
                    }
                    mapAttributes.put(com.getProtectedAttributeNames()[i], plainAttributeNames[i]);
                }

                // Second, decipher the contents
                for (int i = 0; i < content.length; i++) {
                    String[] row = new String[plainAttributeNames.length]; // Reconstructed row
                    boolean selected = true; // to decide if the row should be included in teh result or not
                    for (int j = 0; j < plainAttributeNames.length; j++) {
                        // We assume the attribute names are in the same order of the content
                        // Get the selectors of this attribute
                        List<Select> attributeSelectors = selectorsSet.get(plainAttributeNames[j]);
                        // if no selectors were found, simply insert the identity
                        if (attributeSelectors == null)
                            attributeSelectors = new ArrayList<>();
                        // Do not forget the filters applied to "all";
                        if (selectorsSet.get("all") != null) {
                            attributeSelectors.addAll(selectorsSet.get("all"));
                        }

                        String plainValue;
                        // Get the proteciton type of this attribute
                        String protection = this.typesProtection.get(this.attributeTypes.get(plainAttributeNames[j]));

                        // Decrypt only if the protection type is "encryption" or "simple"
                        if (protection.equals("encryption") || protection.equals("simple")) {
                            // Get the dataID
                            String dataID = this.typesDataIDs.get(this.attributeTypes.get(plainAttributeNames[j]));

                            // Get the Key, Initialization Vector and initialize the Cipher
                            SecretKey key = this.keyStore.retrieveKey(dataID);
                            IvParameterSpec iv = new IvParameterSpec(this.keyStore.retrieveInitVector(dataID));

                            // Initialize the required instances of Ciphers
                            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            cipher.init(Cipher.DECRYPT_MODE, key, iv);

                            // Decipher the value
                            // NOTE - To correctly decrypt, first Base64 decode, THEN decipher
                            byte[] bytesDecContent = cipher.doFinal(decoder.decode(content[i][j].getBytes()));
                            plainValue = new String(bytesDecContent, "UTF-8");
                        } else {
                            // Simply copy the content
                            plainValue = content[i][j];
                        }

                        // Evaluate each attribute selector
                        for (Select selector : attributeSelectors) {
                            // Decide if the row should be selected or not
                            // NOTE - This line gives the "and" semantics to multiple criteria
                            selected = selected && selector.select(plainValue);
                        }
                        row[j] = plainValue;
                    }
                    // Add the column only if all the selectors have passed
                    if (selected) {
                        rowCount++;
                        plainContents.add(row);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }

            // Encapsulate the output
            DataOperationResult command = new EncryptionResult(plainAttributeNames,
                    plainContents.toArray(new String[rowCount][plainAttributeNames.length]));
            commands.add(command);
        }
        return commands;
    }

    @Override
    public List<DataOperationCommand> post(String[] attributeNames, String[][] contents) {
        String[][] encContents = new String[contents.length][attributeNames.length];

        Base64.Encoder encoder = Base64.getEncoder();

        try {
            byte[] bytesContentEnc;

            // Second, obfuscate the contents
            for (int i = 0; i < contents.length; i++) {
                for (int j = 0; j < attributeNames.length; j++) {
                    // Get the prpteciton type of this attribute
                    String protection = this.typesProtection.get(this.attributeTypes.get(attributeNames[j]));
                    // Encrypt only if the protection type is "encryption" or "simple"
                    if (protection.equals("encryption") || protection.equals("simple")) {
                        // Get the dataID
                        String dataID = this.typesDataIDs.get(this.attributeTypes.get(attributeNames[j]));

                        // Get the Key, Initialization Vector and initialize the Cipher
                        SecretKey key = this.keyStore.retrieveKey(dataID);
                        IvParameterSpec iv = new IvParameterSpec(this.keyStore.retrieveInitVector(dataID));

                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

                        // NOTE - To correctly encrypt, First cipher, THEN Base64 encode
                        bytesContentEnc = cipher.doFinal(contents[i][j].getBytes());
                        encContents[i][j] = encoder.encodeToString(bytesContentEnc);
                    } else {
                        // Simply copy the content
                        encContents[i][j] = contents[i][j];
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

        // Generate the ORDERED list of the protected attributeNames
        List<String> protectedAttributes = new ArrayList<>();
        Stream.of(attributeNames)
                .forEach(attributeName -> protectedAttributes.add(this.attributesMapping.get(attributeName)));

        // Encapsulate the output
        DataOperationCommand command = new EncryptionCommand(attributeNames,
                protectedAttributes.toArray(new String[attributeNames.length]), encContents, this.attributesMapping,
                null);
        List<DataOperationCommand> commands = new ArrayList<>();
        commands.add(command);
        return commands;
    }

    @Override
    public List<DataOperationCommand> put(String[] attributeNames, Criteria[] criteria, String[][] contents) {
        // This module does not use PUT method
        return null;
    }

    @Override
    public List<DataOperationCommand> delete(String[] attributeNames, Criteria[] criteria) {
        // This module does not use DELETE method
        return null;
    }

    @Override
    public List<Map<String, String>> head(String[] attributeNames) {
        List<Map<String, String>> aux = new ArrayList<>();
        for (int i = 0; i < this.cloudsNumber; i++) {
            // Insert the Mapping in the first place
            aux.add(i == 0 ? this.attributesMapping : new HashMap<>());
        }
        return aux;
    }
}
