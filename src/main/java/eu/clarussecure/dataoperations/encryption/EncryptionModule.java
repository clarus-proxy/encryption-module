package eu.clarussecure.dataoperations.encryption;

import eu.clarussecure.dataoperations.Criteria;
import eu.clarussecure.dataoperations.DataOperation;
import eu.clarussecure.dataoperations.DataOperationCommand;
import eu.clarussecure.dataoperations.DataOperationResult;
import eu.clarussecure.dataoperations.Mapping;
import eu.clarussecure.dataoperations.encryption.operators.Select;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class EncryptionModule implements DataOperation {

    protected String attributeNamesKey = "Bar12345Bar12345"; // 16 chars * 8 bits = 128 bits cipher
    protected String attributesInitVector = "RandomInitVector"; // Random 16 bytes Init Vector

    // Data extracted from the security policy
    protected Map<String, String> attributeTypes = new HashMap<>(); // name->type
    protected Map<String, String> typesProtection = new HashMap<>(); // type->protectionModule
    protected Map<String, String> typesDataIDs = new HashMap<>(); // type->idKey
    protected KeyStore keyStore = new KeyStore();

    public EncryptionModule(Document policy) {
        // First, get the types of each attribute and build the map
        NodeList nodes = policy.getElementsByTagName("attribute");
        for (int i = 0; i < nodes.getLength(); i++) {
            // Get the node and the list of its attributes
            Node node = nodes.item(i);
            NamedNodeMap attributes = node.getAttributes();
            // Extract the reuqired attributes
            String attributeName = attributes.getNamedItem("name").getNodeValue();
            String attributeType = attributes.getNamedItem("attribute_type").getNodeValue();
            // Add the information to the map
            this.attributeTypes.put(attributeName, attributeType);
        }

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
                this.typesDataIDs.put(typeProtection, dataID);
            }
        }
    }

    @Override
    public List<DataOperationCommand> get(String[] attributeNames, Criteria[] criteria) {
        // IMPORTANT REMARK:
        // Since the encryption is not homomorphic, all the data must be retrieved
        // The selection of the rows will be done in the outboud GET, after decrypting the data
        // First, obfuscate the required attribute names
        String[] encAttributeNames = new String[attributeNames.length];
        Mapping mapAttributes = new Mapping();
        Base64.Encoder encoder = Base64.getEncoder();

        try {
            byte[][] byteAttributeNamesEnc;

            // Initialize the Secret Key and the Init Vector of the Cipher
            IvParameterSpec iv = new IvParameterSpec(this.attributesInitVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(this.attributeNamesKey.getBytes("UTF-8"), "AES");

            // Initialize the required instances of Ciphers
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            // First, obfuscate the attribute Names and map them to the original ones
            byteAttributeNamesEnc = new byte[attributeNames.length][];
            for (int i = 0; i < attributeNames.length; i++) {
                // NOTE - To correctly encrypt, First cipher, THEN Base64 encode
                byteAttributeNamesEnc[i] = cipher.doFinal(attributeNames[i].getBytes());
                encAttributeNames[i] = encoder.encodeToString(byteAttributeNamesEnc[i]);
                mapAttributes.put(attributeNames[i], encAttributeNames[i]);
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

        // Third, create the Comman object
        DataOperationCommand command = new EncryptionCommand(attributeNames, encAttributeNames, null, mapAttributes,
                criteria);
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
            Mapping mapAttributes = new Mapping();

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

            // Second, decipher the data
            try {
                // First, decipher the attribute Names and map them to the origial ones
                for (int i = 0; i < com.getProtectedAttributeNames().length; i++) {
                    // Initialize the Secret Key and the Init Vector of the Cipher
                    IvParameterSpec iv = new IvParameterSpec(attributesInitVector.getBytes("UTF-8"));
                    SecretKeySpec skeySpec = new SecretKeySpec(this.attributeNamesKey.getBytes("UTF-8"), "AES");

                    // Initialize the required instances of Ciphers
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                    // NOTE - To correctly decrypt, first Base64 decode, THEN decipher
                    byte[] bytesEncAttributeName = cipher.doFinal(decoder.decode(com.getProtectedAttributeNames()[i]));
                    plainAttributeNames[i] = new String(bytesEncAttributeName);
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
                        String protection = typesProtection.get(this.attributeTypes.get(plainAttributeNames[j]));

                        // Encrypt only if the protection type is "encryption" or "simple"
                        if (protection.equals("encryption") || protection.equals("simple")) {
                            // Get the encryption parameters of the attribute
                            String dataID = this.typesDataIDs.get(this.attributeTypes.get(plainAttributeNames[j]));
                            String key = this.keyStore.retrieveKey(dataID);
                            String initVector = this.keyStore.retrieveInitVector(dataID);

                            // Initialize the Secret Key and the Init Vector of the Cipher
                            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
                            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

                            // Initialize the required instances of Ciphers
                            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

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

        String[] encAttributeNames = new String[attributeNames.length];
        String[][] encContents = new String[contents.length][attributeNames.length];
        Mapping mapAttributes = new Mapping();

        Base64.Encoder encoder = Base64.getEncoder();

        try {
            byte[][] byteAttributeNamesEnc;
            byte[][][] bytesContentEnc;

            // First, obfuscate the attribute Names and map them to the original ones
            byteAttributeNamesEnc = new byte[attributeNames.length][];
            for (int i = 0; i < attributeNames.length; i++) {
                // Initialize the Secret Key and the Init Vector of the Cipher
                IvParameterSpec iv = new IvParameterSpec(attributesInitVector.getBytes("UTF-8"));
                SecretKeySpec skeySpec = new SecretKeySpec(this.attributeNamesKey.getBytes("UTF-8"), "AES");

                // Initialize the required instances of Ciphers
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
                // NOTE - To correctly encrypt, First cipher, THEN Base64 encode
                // Check 
                byteAttributeNamesEnc[i] = cipher.doFinal(attributeNames[i].getBytes());
                encAttributeNames[i] = encoder.encodeToString(byteAttributeNamesEnc[i]);
                mapAttributes.put(attributeNames[i], encAttributeNames[i]);
            }

            // Second, obfuscate the contents
            bytesContentEnc = new byte[contents.length][attributeNames.length][];
            for (int i = 0; i < contents.length; i++) {
                for (int j = 0; j < attributeNames.length; j++) {
                    // Get the prpteciton type of this attribute
                    String protection = typesProtection.get(this.attributeTypes.get(attributeNames[j]));
                    // Encrypt only if the protection type is "encryption" or "simple"
                    if (protection.equals("encryption") || protection.equals("simple")) {
                        // Get the key
                        String dataID = this.typesDataIDs.get(this.attributeTypes.get(attributeNames[j]));
                        String key = this.keyStore.retrieveKey(dataID);
                        String initVector = this.keyStore.retrieveInitVector(dataID);
                        // Initialize the Cipher
                        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
                        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

                        // NOTE - To correctly encrypt, First cipher, THEN Base64 encode
                        bytesContentEnc[i][j] = cipher.doFinal(contents[i][j].getBytes());
                        encContents[i][j] = encoder.encodeToString(bytesContentEnc[i][j]);
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

        // Encapsulate the output
        DataOperationCommand command = new EncryptionCommand(attributeNames, encAttributeNames, encContents,
                mapAttributes, null);
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
    public List<Mapping> head(String[] attributeNames) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
