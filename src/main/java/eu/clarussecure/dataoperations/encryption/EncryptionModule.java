package eu.clarussecure.dataoperations.encryption;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.postgis.PGbox2d;
import org.postgis.Point;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.apache.commons.codec.binary.Hex;

import eu.clarussecure.dataoperations.AttributeNamesUtilities;
import eu.clarussecure.dataoperations.Criteria;
import eu.clarussecure.dataoperations.DataOperation;
import eu.clarussecure.dataoperations.DataOperationCommand;
import eu.clarussecure.dataoperations.DataOperationResult;
import eu.clarussecure.dataoperations.geometry.GeometryBuilder;
import eu.clarussecure.dataoperations.geometry.ProjectedCRS;

public class EncryptionModule implements DataOperation {

    // This string is a flag to identify attributes that are not covered in the
    // security policy
    // It is used actively by the HEAD function.
    protected static final String TO_BE_FILTERED_FLAG = "NOT_COVERED";

    // Data extracted from the security policy
    // NOTE: key set of attributeTypes CAN HAVE wildcards to match more than one
    // attribute
    protected Map<String, String> attributeTypes = new HashMap<>(); // qualifName->type
    protected Map<String, String> dataTypes = new HashMap<>(); // qualifName->data
                                                               // type
    protected Map<String, String> typesProtection = new HashMap<>(); // type->protectionModule
    protected Map<String, String> typesDataIDs = new HashMap<>(); // type->idKey
    protected KeyStore keyStore = KeyStore.getInstance();

    // ISSUE 3 - This flag was intreoduced to mark all the attribute types
    // declared in the "data" section of the XML
    protected final static String NULL_PROTECTION_FLAG = "NULL_PROTECTION";

    // Mapping to determine where to store each qualified name
    protected int cloudsNumber;
    // protected Map<String, Integer> attributeClouds = new HashMap<>();

    public EncryptionModule(Document policy) {
        // TODO - Extract the number of "endpoints" (aka Clouds) from the
        // policy.
        // At this point this number WILL BE HARD CODED!!!
        this.cloudsNumber = 1;

        // First, get the types of each attribute and build the map
        NodeList nodes = policy.getElementsByTagName("attribute");
        for (int i = 0; i < nodes.getLength(); i++) {
            // Get the node and the list of its attributes
            Node node = nodes.item(i);
            NamedNodeMap attributes = node.getAttributes();
            // Extract the required attributes
            String attributeName = attributes.getNamedItem("name").getNodeValue();
            String attributeType = attributes.getNamedItem("attribute_type").getNodeValue();
            String dataType = attributes.getNamedItem("data_type").getNodeValue();
            // Add the information to the map
            this.attributeTypes.put(attributeName, attributeType);
            this.dataTypes.put(attributeName, dataType);
            // ISSUE 3 - Concerning attribute types not protected.
            // The problem raises because not all the attribute types declared in
            // attributes list are associated with a protection module (or a "null"
            // protection module)
            // At this point, we are analyzing ALL the declared attributes
            // Use this opportunity to pre-fill the typesProtection map
            this.typesProtection.put(attributeType, EncryptionModule.NULL_PROTECTION_FLAG);
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
            // Get the idKey only if the protection module is "encryption" or
            // "simple"
            if (typeProtection.equals("encryption") || typeProtection.equals("simple")) {
                String dataID = attributes.getNamedItem("id_key").getNodeValue();
                this.typesDataIDs.put(attributeType, dataID);
            }
        }
        // FIXME - Should the policy specify in which cloud to store the
        // encrypted data?
        // If so, this information should be available in the "attribute_type"
        // tag
        // so the "mapping" showing where to store each attribute should be
        // built here.
        /*
         * Example: <endpoint id=1 protocol="prot" port="12345"> <parameters>
         * <parameter param="name1" value="val1" /> </parameters> </endpoint>
         * <endpoint id=2 protocol="prot1" port="98765"> <parameters> <parameter
         * param="name3" value="val12" /> </parameters> </endpoint> ...
         * <attribute_type type="confidential" protection="encryption"
         * id_key="176" cloud="1">
         */
        // At the moment, the mapping will be done assuming the encrypted
        // attributes go to the first cloud
        // this.forEach(qualifiedName -> this.attributeClouds.put(qualifiedName,
        // 0));
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        this.keyStore.deleteInstance();
    }

    @Override
    public List<DataOperationCommand> get(String[] attributeNames, Criteria[] criteria) {
        // IMPORTANT REMARK:
        // Since the encryption is not homomorphic, all the data must be
        // retrieved
        // The selection of the rows will be done in the outboud GET, after
        // decrypting the data

        Map<String, String> attributesMapping = this.buildAttributesMapping(attributeNames,
                notCoveredAttribute -> notCoveredAttribute, unprotectedAttrib -> unprotectedAttrib);

        // First, Generate the ORDERED list of the protected attributeNames
        List<String> protectedAttributes = new ArrayList<>();
        Stream.of(attributeNames)
                .forEach(attributeName -> protectedAttributes.add(attributesMapping.get(attributeName)));

        // Second, process the Criteria to transform the requested
        // AttributeNames to the protected ones
        if (criteria != null) {
            Stream.of(criteria).forEach(criterion -> {
                // Determine if the column is encrypted of not
                String protectedAttribute = attributesMapping.get(criterion.getAttributeName());
                if (!criterion.getAttributeName().equals(protectedAttribute)) {
                    // The protected and unprotected Attribute Names do not
                    // match
                    // This implies the criteria operates over an encrypted
                    // column
                    // First, modify the operator to use a String comparator
                    // criterion.setOperator("s=");
                    // Second, encrypt the treshold
                    String protectedThreshold = "";
                    try {
                        // Find which "protectionRule" (in the keyset of attributeTypes) matches the given attribute name
                        String matchedProtection = null;
                        for (String protectionRule : this.attributeTypes.keySet()) {
                            Pattern p = Pattern.compile(AttributeNamesUtilities.escapeRegex(protectionRule));
                            if (p.matcher(criterion.getAttributeName()).matches()) {
                                matchedProtection = protectionRule;
                            }
                        }

                        // If none matches, ignore this attribute => it is not convered by the Policy
                        if (matchedProtection == null)
                            return;

                        // Obtain the dataID
                        String dataID = this.typesDataIDs.get(this.attributeTypes.get(matchedProtection));

                        // Get the prpteciton type of this attribute
                        String protection = this.typesProtection.get(this.attributeTypes.get(matchedProtection));
                        // Encrypt only if the protection type is "encryption"
                        // or "simple"
                        if (protection.equals("encryption") || protection.equals("simple")) {
                            byte[] bytesAttribEnc;

                            // Initialize the Secret Key and the Init Vector of
                            // the Cipher
                            IvParameterSpec iv = new IvParameterSpec(this.keyStore.retrieveInitVector(dataID));
                            SecretKey sk = this.keyStore.retrieveKey(dataID);

                            if (this.dataTypes.get(matchedProtection).equals("geometric_object")) {
                                String value = criterion.getValue();

                                if (criterion.getOperator().equals("area")) {
                                    String[] area = value.split(",");
                                    value = String.format("SRID=%s;BOX(%s %s, %s %s)", area[4].trim(), area[0].trim(),
                                            area[1].trim(), area[2].trim(), area[3].trim());
                                }

                                GeometryBuilder builder = new GeometryBuilder();
                                Object geom = builder.decode(value);
                                if (geom != null) {
                                    if (geom instanceof Point) {
                                        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
                                        cipher.init(Cipher.ENCRYPT_MODE, sk, iv);

                                        // NOTE - To correctly encrypt, just cipher coordinates
                                        Point point = (Point) geom;
                                        double maxX, maxY;
                                        int srid = point.getSrid();
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            maxX = crs.getAxis("x").getMax();
                                            maxY = crs.getAxis("y").getMax();
                                        } else {
                                            maxX = Double.MAX_VALUE;
                                            maxY = Double.MAX_VALUE;
                                        }
                                        point.x = encryptDouble(cipher, point.x, maxX);
                                        point.y = encryptDouble(cipher, point.y, maxY);
                                    } else if (geom instanceof PGbox2d) {
                                        PGbox2d box = (PGbox2d) geom;
                                        int srid = box.getLLB().getSrid();
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            box.getLLB().x = crs.getAxis("x").getMin();
                                            box.getLLB().y = crs.getAxis("y").getMin();
                                            box.getURT().x = crs.getAxis("x").getMax();
                                            box.getURT().y = crs.getAxis("y").getMax();
                                        } else {
                                            box.getLLB().x = -Double.MAX_VALUE;
                                            box.getLLB().y = -Double.MAX_VALUE;
                                            box.getURT().x = Double.MAX_VALUE;
                                            box.getURT().y = Double.MAX_VALUE;
                                        }
                                        if (criterion.getOperator().equals("area")) {
                                            value = box.getLLB().x + ", " + box.getLLB().y + ", " + box.getURT().x
                                                    + ", " + box.getURT().y + ", " + srid;
                                        }
                                    }
                                    if (!criterion.getOperator().equals("area")) {
                                        value = builder.encode(geom);
                                    }
                                }
                                protectedThreshold = value;
                            } else {
                                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                cipher.init(Cipher.ENCRYPT_MODE, sk, iv);

                                // NOTE - To correctly encrypt, First cipher, THEN
                                // use the String encoder
                                String value = criterion.getValue() != null ? criterion.getValue() : "clarus_null";
                                bytesAttribEnc = cipher.doFinal(value.getBytes());
                                protectedThreshold = Hex.encodeHexString(bytesAttribEnc, true);
                            }
                        } else {
                            // Otherwise, just let the value pass in plain text
                            protectedThreshold = criterion.getValue();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.exit(1);
                    }
                    criterion.setValue(protectedThreshold);
                    // Third, substitute the involved attribute name with its
                    // protected one
                    criterion.setAttributeName(attributesMapping.get(criterion.getAttributeName()));
                }
            });
        }

        // Third, create the Comman object
        DataOperationCommand command = new EncryptionCommand(attributeNames,
                protectedAttributes.toArray(new String[attributeNames.length]), null, attributesMapping, criteria);
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

            // Second, decipher the attribute names
            try {
                // First, decipher the attribute Names and map them to the
                // original ones
                // Get the mapping of the protected attributes
                Map<String, String> protAttribNames = com.getMapping();
                // "Invert" The Mapping
                Map<String, String> invertedMap = protAttribNames.entrySet().stream()
                        .collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));
                for (int i = 0; i < com.getProtectedAttributeNames().length; i++) {
                    // The "_enc" suffix was added to identify encrypted attributes
                    if (com.getProtectedAttributeNames()[i].endsWith("_enc")) {
                        // As we have the "inverted" mapping, deciphering is as
                        // simple as map the encrypted values
                        plainAttributeNames[i] = invertedMap.get(com.getProtectedAttributeNames()[i]);
                    } else {
                        plainAttributeNames[i] = com.getProtectedAttributeNames()[i];
                    }
                    mapAttributes.put(com.getProtectedAttributeNames()[i], plainAttributeNames[i]);
                }

                // Second, decipher the contents
                for (int i = 0; i < content.length; i++) {
                    String[] row = new String[plainAttributeNames.length]; // Reconstructed
                                                                           // row
                    for (int j = 0; j < plainAttributeNames.length; j++) {
                        // Find which "protectionRule" (in the keyset of
                        // attributeTypes) matches the given attribute name
                        String matchedProtection = null;
                        for (String protectionRule : this.attributeTypes.keySet()) {
                            Pattern p = Pattern.compile(AttributeNamesUtilities.escapeRegex(protectionRule));
                            if (p.matcher(plainAttributeNames[j]).matches()) {
                                matchedProtection = protectionRule;
                            }
                        }

                        // If none matches, ignore this attribute => it is not
                        // convered by the Policy
                        if (matchedProtection == null)
                            continue;

                        String plainValue;
                        // Get the proteciton type of this attribute
                        String protection = this.typesProtection.get(this.attributeTypes.get(matchedProtection));

                        // Decrypt only if the protection type is "encryption"
                        // or "simple"
                        if (protection.equals("encryption") || protection.equals("simple")) {
                            // Get the dataID
                            String dataID = this.typesDataIDs.get(this.attributeTypes.get(matchedProtection));

                            // Get the Key, Initialization Vector and initialize
                            // the Cipher
                            SecretKey key = this.keyStore.retrieveKey(dataID);
                            IvParameterSpec iv = new IvParameterSpec(this.keyStore.retrieveInitVector(dataID));

                            if (this.dataTypes.get(matchedProtection).equals("geometric_object")) {
                                String value = content[i][j];
                                GeometryBuilder builder = new GeometryBuilder();
                                Object geom = builder.decode(value);
                                if (geom != null) {
                                    if (geom instanceof Point) {
                                        // Initialize the required instances of Ciphers
                                        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
                                        cipher.init(Cipher.DECRYPT_MODE, key, iv);

                                        // NOTE - To correctly encrypt, just cipher coordinates
                                        Point point = (Point) geom;
                                        double maxX, maxY;
                                        int srid = point.getSrid();
                                        if (srid == 0) {
                                            srid = Arrays.stream(com.getCriteria())
                                                    .filter(c -> c.getOperator().equals("area")).findFirst()
                                                    .map(Criteria::getValue).map(v -> v.split(",")).map(tk -> tk[4])
                                                    .map(String::trim).map(Integer::parseInt).orElse(0);
                                        }
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            maxX = crs.getAxis("x").getMax();
                                            maxY = crs.getAxis("y").getMax();
                                        } else {
                                            maxX = Double.MAX_VALUE;
                                            maxY = Double.MAX_VALUE;
                                        }
                                        point.x = decryptDouble(cipher, point.x, maxX);
                                        point.y = decryptDouble(cipher, point.y, maxY);
                                    } else if (geom instanceof PGbox2d) {
                                        PGbox2d box = (PGbox2d) geom;
                                        int srid = box.getLLB().getSrid();
                                        if (srid == 0) {
                                            srid = Arrays.stream(com.getCriteria())
                                                    .filter(c -> c.getOperator().equals("area")).findFirst()
                                                    .map(Criteria::getValue).map(v -> v.split(",")).map(tk -> tk[4])
                                                    .map(String::trim).map(Integer::parseInt).orElse(0);
                                        }
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            box.getLLB().x = crs.getAxis("x").getMin();
                                            box.getLLB().y = crs.getAxis("y").getMin();
                                            box.getURT().x = crs.getAxis("x").getMax();
                                            box.getURT().y = crs.getAxis("y").getMax();
                                        } else {
                                            box.getLLB().x = -Double.MAX_VALUE;
                                            box.getLLB().y = -Double.MAX_VALUE;
                                            box.getURT().x = Double.MAX_VALUE;
                                            box.getURT().y = Double.MAX_VALUE;
                                        }
                                    }
                                    value = builder.encode(geom);
                                }
                                plainValue = value;
                            } else {
                                // Initialize the required instances of Ciphers
                                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                cipher.init(Cipher.DECRYPT_MODE, key, iv);

                                // Decipher the value
                                // NOTE - To correctly decrypt, first use the
                                // String decoder, THEN decipher
                                byte[] bytesDecContent = cipher.doFinal(Hex.decodeHex(content[i][j]));
                                plainValue = new String(bytesDecContent);
                                if ("clarus_null".equals(plainValue)) {
                                    plainValue = null;
                                }
                            }
                        } else {
                            // Simply copy the content
                            plainValue = content[i][j];
                        }
                        // Add the computed value (deciphered or not to the row
                        row[j] = plainValue;
                    }
                    // Add the row to the final result
                    plainContents.add(row);
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

        // Create the mapping between the given Attribute Names and the protected ones.
        // This method uses the "buildAttributesMapping" function, letting the not covered and unprotected attributes pass
        // (i.e. not marking them since this mapping WILL NOT be filtered later)
        Map<String, String> attributesMapping = this.buildAttributesMapping(attributeNames,
                notCoveredAttrib -> notCoveredAttrib, unprotectedAttrib -> unprotectedAttrib);

        try {
            byte[] bytesContentEnc;

            // Second, obfuscate the contents
            for (int i = 0; i < contents.length; i++) {
                for (int j = 0; j < attributeNames.length; j++) {
                    // Get the prpteciton type of this attribute
                    // Find which "protectionRule" (in the keyset of attributeTypes) matches the given attribute name
                    String matchedProtection = null;
                    for (String protectionRule : this.attributeTypes.keySet()) {
                        Pattern p = Pattern.compile(AttributeNamesUtilities.escapeRegex(protectionRule));
                        if (p.matcher(attributeNames[j]).matches()) {
                            matchedProtection = protectionRule;
                        }
                    }

                    // If none matches, ignore this attribute => it is not convered by the Policy
                    if (matchedProtection == null)
                        continue;

                    String protection = this.typesProtection.get(this.attributeTypes.get(matchedProtection));
                    // Encrypt only if the protection type is "encryption" or "simple"
                    if (protection.equals("encryption") || protection.equals("simple")) {
                        // Get the dataID
                        String dataID = this.typesDataIDs.get(this.attributeTypes.get(matchedProtection));

                        // Get the Key, Initialization Vector and initialize the Cipher
                        SecretKey key = this.keyStore.retrieveKey(dataID);
                        IvParameterSpec iv = new IvParameterSpec(this.keyStore.retrieveInitVector(dataID));

                        if (this.dataTypes.get(matchedProtection).equals("geometric_object")) {
                            Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
                            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

                            String value = contents[i][j];
                            GeometryBuilder builder = new GeometryBuilder();
                            Object geom = null;
                            try {
                                geom = builder.decode(value);
                            }
                            // in case the value is not in WKT format (e.g. GML for WFS)
                            catch (java.lang.StringIndexOutOfBoundsException e) {
                                geom = new Point(String.format("POINT(%s)",value));
                            }
                            if (geom != null) {
                                // NOTE - To correctly encrypt, just cipher coordinates
                                if (geom instanceof Point) {
                                    Point point = (Point) geom;
                                    double maxX, maxY;
                                    int srid = point.getSrid();
                                    if (srid != 0) {
                                        ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                        maxX = crs.getAxis("x").getMax();
                                        maxY = crs.getAxis("y").getMax();
                                    } else {
                                        maxX = Double.MAX_VALUE;
                                        maxY = Double.MAX_VALUE;
                                    }
                                    point.x = encryptDouble(cipher, point.x, maxX);
                                    point.y = encryptDouble(cipher, point.y, maxY);
                                }
                                value = builder.encode(geom);
                            }
                            encContents[i][j] = value;
                        } else {
                            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

                            // NOTE - To correctly encrypt, First cipher, THEN
                            // use the String encoder
                            String content = contents[i][j] != null ? contents[i][j] : "clarus_null";
                            bytesContentEnc = cipher.doFinal(content.getBytes());
                            encContents[i][j] = Hex.encodeHexString(bytesContentEnc, true);
                        }
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
                .forEach(attributeName -> protectedAttributes.add(attributesMapping.get(attributeName)));

        // Encapsulate the output
        DataOperationCommand command = new EncryptionCommand(attributeNames,
                protectedAttributes.toArray(new String[attributeNames.length]), encContents, attributesMapping, null);
        List<DataOperationCommand> commands = new ArrayList<>();
        commands.add(command);
        return commands;
    }

    private double encryptDouble(Cipher cipher, double value, double maxValue)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        long rawBits = Double.doubleToRawLongBits(value); // e.g. clear: 0xa3412345678abcde
        // separate encryption of the exponent and of the significand to
        // preserve validity regarding the range of valid values
        long sign = rawBits & 0x8000000000000000L; // e.g. clear: 0x8000000000000000
        long exponent = rawBits & 0x7ff0000000000000L; // e.g. clear: 0x2340000000000000
        long significand = rawBits & 0x000fffffffffffffL; // e.g. clear: 0x00012345678abcde
        // encrypt significand using the provided cipher
        significand = significand << 4; // e.g. clear: 0x0012345678abcde0
        byte[] bytesContent = toByteArray(significand);
        bytesContent = swapByteArray(bytesContent); // e.g. clear: 0xe0cdab7856341200
        bytesContent[0] = (byte) ((bytesContent[0] & 0xff) >>> 4); // e.g. clear: 0x0ecdab7856341200
        significand = toLong(bytesContent);
        significand = significand >>> 8; // e.g. clear: 0x000ecdab78563412
        bytesContent = toByteArray(significand);
        byte[] bytesContentEnc = new byte[bytesContent.length];
        bytesContentEnc[0] = bytesContent[0]; // e.g. encrypted: 0x0000000000000000
        bytesContentEnc[1] = bytesContent[1]; // e.g. encrypted: 0x000e000000000000
        cipher.doFinal(bytesContent, 2, bytesContent.length - 2, bytesContentEnc, 2);
        significand = toLong(bytesContentEnc); // e.g. encrypted: 0x000e(cdab78563412)
        // encrypt the exponent using XOR cipher
        short expo = (short) (exponent >>> 52); // e.g. clear: 0x0234
        long rawBitsMax = Double.doubleToRawLongBits(maxValue); // e.g. clear: 0xc1731940863d70a4
        long exponentMax = rawBitsMax & 0x7ff0000000000000L; // e.g. clear: 0xc170000000000000
        short expoMax = (short) (exponentMax >>> 52); // e.g. clear: 0x0c17
        int highestLeadingBit = 32 - Integer.numberOfLeadingZeros(expoMax) - 1; // e.g. 10
        short lowestBitsMask = (short) ((1 << highestLeadingBit) - 1); // e.g. 0x03ff
        short highestBitsMask = (short) ~lowestBitsMask; // e.g. 0xfc00
        short xorMask = (short) (expoMax & lowestBitsMask); // e.g. 0x0017
        expo = (short) ((expo & highestBitsMask) // e.g. encrypted: 0x02(23)
                | ((expo & lowestBitsMask) ^ xorMask));
        exponent = (long) expo << 52; // e.g. encrypted: 0x2(23)0000000000000
        rawBits = sign | exponent | significand; // e.g. encrypted: 0xa(23)e(cdab78563412)
        value = Double.longBitsToDouble(rawBits);
        return value;
    }

    private double decryptDouble(Cipher cipher, double value, double maxValue)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        long rawBits = Double.doubleToRawLongBits(value); // e.g. encrypted: 0xa(23)e(cdab78563412)
        // separate decryption of the exponent and of the significand to
        // preserve validity regarding the range of valid values
        long sign = rawBits & 0x8000000000000000L; // e.g. encrypted: 0x8000000000000000
        long exponent = rawBits & 0x7ff0000000000000L; // e.g. encrypted: 0x2(23)0000000000000
        long significand = rawBits & 0x000fffffffffffffL; // e.g. encrypted: 0x000e(cdab78563412)
        // decrypt the significand using the provided cipher
        byte[] bytesContent = toByteArray(significand);
        byte[] bytesDecContent = new byte[bytesContent.length];
        bytesDecContent[0] = bytesContent[0]; // e.g. clear: 0x0000000000000000
        bytesDecContent[1] = bytesContent[1]; // e.g. clear: 0x000e000000000000
        cipher.doFinal(bytesContent, 2, bytesContent.length - 2, bytesDecContent, 2);
        significand = toLong(bytesDecContent); // e.g. clear: 0x000ecdab78563412
        significand = significand << 8; // e.g. clear: 0x0ecdab7856341200
        bytesDecContent = toByteArray(significand);
        bytesDecContent[0] = (byte) (bytesDecContent[0] << 4); // e.g. clear: 0xe0cdab7856341200
        bytesDecContent = swapByteArray(bytesDecContent); // e.g. clear: 0x0012345678abcde0
        significand = toLong(bytesDecContent);
        significand = significand >>> 4; // e.g. clear: 0x00012345678abcde
        // decrypt the exponent using XOR cipher
        short expo = (short) (exponent >>> 52); // e.g. encrypted: 0x02(23)
        long rawBitsMax = Double.doubleToRawLongBits(maxValue); // e.g. clear: 0xc1731940863d70a4
        long exponentMax = rawBitsMax & 0x7ff0000000000000L; // e.g. clear: 0xc170000000000000
        short expoMax = (short) (exponentMax >>> 52); // e.g. clear: 0x0c17
        int highestLeadingBit = 32 - Integer.numberOfLeadingZeros(expoMax) - 1; // e.g. 10
        short lowestBitsMask = (short) ((1 << highestLeadingBit) - 1); // e.g. 0x03ff
        short highestBitsMask = (short) ~lowestBitsMask; // e.g. 0xfc00
        short xorMask = (short) (expoMax & lowestBitsMask); // e.g. 0x0017
        expo = (short) ((expo & highestBitsMask) // e.g. encrypted: 0x0234
                | ((expo & lowestBitsMask) ^ xorMask));
        exponent = (long) expo << 52; // e.g. clear: 0x2340000000000000
        rawBits = sign | exponent | significand; // e.g. clear: 0xa3412345678abcde
        value = Double.longBitsToDouble(rawBits);
        return value;
    }

    private byte[] swapByteArray(byte[] value) {
        for (int i = 0; i < value.length / 2; i++) {
            byte b = value[i];
            value[i] = value[value.length - i - 1];
            value[value.length - i - 1] = b;
        }
        return value;
    }

    private byte[] toByteArray(long value) {
        return new byte[] { (byte) (value >>> 56), (byte) (value >>> 48), (byte) (value >>> 40), (byte) (value >>> 32),
                (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value };
    }

    private long toLong(byte[] value) {
        return ((long) value[0] & 0xff) << 56 | ((long) value[1] & 0xff) << 48 | ((long) value[2] & 0xff) << 40
                | ((long) value[3] & 0xff) << 32 | ((long) value[4] & 0xff) << 24 | ((long) value[5] & 0xff) << 16
                | ((long) value[6] & 0xff) << 8 | (long) value[7] & 0xff;
    }

    @Override
    public List<DataOperationCommand> put(String[] attributeNames, Criteria[] criteria, String[][] contents) {
        // This module does not use PUT method
        return null;
    }

    @Override
    public List<DataOperationCommand> delete(String[] attributeNames, Criteria[] criteria) {
        Map<String, String> attributesMapping = this.buildAttributesMapping(attributeNames,
                notCoveredAttribute -> notCoveredAttribute, unprotectedAttrib -> unprotectedAttrib);

        // First, Generate the ORDERED list of the protected attributeNames
        List<String> protectedAttributes = new ArrayList<>();
        Stream.of(attributeNames)
                .forEach(attributeName -> protectedAttributes.add(attributesMapping.get(attributeName)));

        // Second, process the Criteria to transform the requested
        // AttributeNames to the protected ones
        if (criteria != null) {
            Stream.of(criteria).forEach(criterion -> {
                // Determine if the column is encrypted or not
                String protectedAttribute = attributesMapping.get(criterion.getAttributeName());
                if (!criterion.getAttributeName().equals(protectedAttribute)) {
                    // The protected and unprotected Attribute Names do not
                    // match
                    // This implies the criteria operates over an encrypted
                    // column
                    // Encrypt the treshold
                    String protectedThreshold = "";
                    try {
                        // Find which "protectionRule" (in the keyset of attributeTypes) matches the given attribute name
                        String matchedProtection = null;
                        for (String protectionRule : this.attributeTypes.keySet()) {
                            Pattern p = Pattern.compile(AttributeNamesUtilities.escapeRegex(protectionRule));
                            if (p.matcher(criterion.getAttributeName()).matches()) {
                                matchedProtection = protectionRule;
                            }
                        }

                        // If none matches, ignore this attribute => it is not convered by the Policy
                        if (matchedProtection == null)
                            return;

                        // Obtain the dataID
                        String dataID = this.typesDataIDs.get(this.attributeTypes.get(matchedProtection));

                        // Get the prpteciton type of this attribute
                        String protection = this.typesProtection.get(this.attributeTypes.get(matchedProtection));
                        // Encrypt only if the protection type is "encryption"
                        // or "simple"
                        if (protection.equals("encryption") || protection.equals("simple")) {
                            byte[] bytesAttribEnc;

                            // Initialize the Secret Key and the Init Vector of
                            // the Cipher
                            IvParameterSpec iv = new IvParameterSpec(this.keyStore.retrieveInitVector(dataID));
                            SecretKey sk = this.keyStore.retrieveKey(dataID);

                            if (this.dataTypes.get(matchedProtection).equals("geometric_object")) {
                                String value = criterion.getValue();

                                if (criterion.getOperator().equals("area")) {
                                    String[] area = value.split(",");
                                    value = String.format("SRID=%s;BOX(%s %s, %s %s)", area[4].trim(), area[0].trim(),
                                            area[1].trim(), area[2].trim(), area[3].trim());
                                }

                                GeometryBuilder builder = new GeometryBuilder();
                                Object geom = builder.decode(value);
                                if (geom != null) {
                                    if (geom instanceof Point) {
                                        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
                                        cipher.init(Cipher.ENCRYPT_MODE, sk, iv);

                                        // NOTE - To correctly encrypt, just cipher coordinates
                                        Point point = (Point) geom;
                                        double maxX, maxY;
                                        int srid = point.getSrid();
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            maxX = crs.getAxis("x").getMax();
                                            maxY = crs.getAxis("y").getMax();
                                        } else {
                                            maxX = Double.MAX_VALUE;
                                            maxY = Double.MAX_VALUE;
                                        }
                                        point.x = encryptDouble(cipher, point.x, maxX);
                                        point.y = encryptDouble(cipher, point.y, maxY);
                                    } else if (geom instanceof PGbox2d) {
                                        PGbox2d box = (PGbox2d) geom;
                                        int srid = box.getLLB().getSrid();
                                        if (srid != 0) {
                                            ProjectedCRS crs = ProjectedCRS.resolve(srid);
                                            box.getLLB().x = crs.getAxis("x").getMin();
                                            box.getLLB().y = crs.getAxis("y").getMin();
                                            box.getURT().x = crs.getAxis("x").getMax();
                                            box.getURT().y = crs.getAxis("y").getMax();
                                        } else {
                                            box.getLLB().x = -Double.MAX_VALUE;
                                            box.getLLB().y = -Double.MAX_VALUE;
                                            box.getURT().x = Double.MAX_VALUE;
                                            box.getURT().y = Double.MAX_VALUE;
                                        }
                                        if (criterion.getOperator().equals("area")) {
                                            value = box.getLLB().x + ", " + box.getLLB().y + ", " + box.getURT().x
                                                    + ", " + box.getURT().y + ", " + srid;
                                        }
                                    }
                                    if (!criterion.getOperator().equals("area")) {
                                        value = builder.encode(geom);
                                    }
                                }
                                protectedThreshold = value;
                            } else {
                                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                cipher.init(Cipher.ENCRYPT_MODE, sk, iv);

                                // NOTE - To correctly encrypt, First cipher, THEN
                                // use the String encoder
                                String value = criterion.getValue() != null ? criterion.getValue() : "clarus_null";
                                bytesAttribEnc = cipher.doFinal(value.getBytes());
                                protectedThreshold = Hex.encodeHexString(bytesAttribEnc, true);
                            }
                        } else {
                            // Otherwise, just let the value pass in plain text
                            protectedThreshold = criterion.getValue();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.exit(1);
                    }
                    criterion.setValue(protectedThreshold);
                    // Third, substitute the involved attribute name with its
                    // protected one
                    criterion.setAttributeName(attributesMapping.get(criterion.getAttributeName()));
                }
            });
        }

        // Third, create the Comman object
        DataOperationCommand command = new EncryptionCommand(attributeNames,
                protectedAttributes.toArray(new String[attributeNames.length]), null, attributesMapping, criteria);
        List<DataOperationCommand> commands = new ArrayList<>();
        commands.add(command);
        return commands;
    }

    @Override
    public List<Map<String, String>> head(String[] attributeNames) {
        // First, resolve the wildcards according to the policy definitions
        String[] resolvedAttributes = AttributeNamesUtilities.resolveOperationAttributeNames(attributeNames,
                new ArrayList<>(this.attributeTypes.keySet()));
        // Remove duplicates here, since the resolved attributes will be the
        // keys of the mapping
        // Let's leave the HashSet class do the magic :)
        Set<String> filteredAttributes = new HashSet<>(Arrays.asList(resolvedAttributes));
        // Then build the Attributes Mapping AND filter the ones not concerned
        Map<String, String> attribsMapping = filterMapingEntries(
                this.buildAttributesMapping(filteredAttributes.toArray(new String[filteredAttributes.size()]),
                        // Not covered Attributes will be marked for later filtering
                        attrib -> EncryptionModule.TO_BE_FILTERED_FLAG,
                        // Not protected Attributes will NOT be marked for later filtering
                        attrib -> attrib));
        List<Map<String, String>> aux = new ArrayList<>();
        for (int i = 0; i < this.cloudsNumber; i++) {
            // Insert the Mapping in the first place
            aux.add(i == 0 ? attribsMapping : new HashMap<>());
        }
        return aux;
    }

    private Map<String, String> filterMapingEntries(Map<String, String> mapping) {
        // This function will analyze the given mapping (built using
        // buildAttributesMapping)
        // and remove the entries that are not comprised in the security policy.
        // Get the Entries set
        Set<Map.Entry<String, String>> entries = mapping.entrySet();
        Set<Map.Entry<String, String>> newEntries = new HashSet<>();
        // Select which entries will remain in the map.
        entries.stream().forEach(entry -> {
            String value = entry.getValue();
            if (!value.equals(EncryptionModule.TO_BE_FILTERED_FLAG)) {
                // if the value WAS NOT marked as "not covered" the entry SHOULD
                // be kept.
                newEntries.add(entry);
            }
        });
        // Reconstruct the final HashMap
        return newEntries.stream().collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private Map<String, String> buildAttributesMapping(String[] attributes,
            Function<String, String> notCoveredTransform, Function<String, String> notProtected) {
        // NOTE: The "notCoveredTransform" function will say what to do with the attributes non-covered by the security policy.
        // NOTE: The "notProtected" function will say what to do with the attributes covered by the security policy but not using this module
        // Create the mapping between the given attribute names and their protected names
        // This mapping must be done considering the list of attributes to protect specified in the security policy
        // Generate the map between qualified Attributes and protected Attributes Names
        Map<String, String> mapping;

        mapping = Arrays.asList(attributes).stream() // Get all the qualified Names
                .collect(Collectors.toMap( // Reduce them into a new Map
                        // Use the same qualified Attribute Name as key
                        originalQualifAttribName -> originalQualifAttribName,
                        // Generate the mapped values: the "encrypted" ones
                        originalQualifAttribName -> {
                            String attribEnc = "";
                            try {
                                // Find which "protectionRule" (in the keyset of
                                // attributeTypes) matches the given attribute
                                // name
                                String matchedProtection = null;
                                for (String protectionRule : this.attributeTypes.keySet()) {
                                    Pattern p = Pattern.compile(AttributeNamesUtilities.escapeRegex(protectionRule));
                                    if (p.matcher(originalQualifAttribName).matches()) {
                                        matchedProtection = protectionRule;
                                    }
                                }

                                // If none matches, ignore this attribute => it
                                // is not convered by the Policy
                                // To filter these entries later, we will use a
                                // "special" string.
                                if (matchedProtection == null)
                                    return notCoveredTransform.apply(originalQualifAttribName);

                                // Obtain the dataID
                                String dataID = this.typesDataIDs.get(this.attributeTypes.get(matchedProtection));

                                // Encrypt the column name only if the policy
                                // says so
                                // Get the prpteciton type of this attribute
                                String protection = this.typesProtection
                                        .get(this.attributeTypes.get(matchedProtection));
                                // Encrypt only if the protection type is
                                // "encryption" or "simple"
                                if (protection.equals("encryption") || protection.equals("simple")) {
                                    // The name of the attribute CAN be
                                    //completely encrypted. Use this code to do
                                    //so
                                    /*
                                    byte[] bytesAttribEnc;

                                    // Initialize the Secret Key and the Init
                                    // Vector of the Cipher
                                    IvParameterSpec iv = new IvParameterSpec(this.keyStore.retrieveInitVector(dataID));
                                    SecretKey sk = this.keyStore.retrieveKey(dataID);

                                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                    cipher.init(Cipher.ENCRYPT_MODE, sk, iv);
                                    // ISSUE - We need to encrypt only the last portion of the
                                    // qualified attribute name
                                    String[] attribParts = originalQualifAttribName.split("/");

                                    // NOTE - To correctly encrypt, First cipher, THEN Base64 encode
                                    bytesAttribEnc = cipher.doFinal(attribParts[2].getBytes());

                                    // Rejoin the qualified attibute name and add the 
                                    // "_enc" suffix to easily identify the protected attributes
                                    // FIX ISSUE # 4
                                    // The Base64 encoding uses the "/" character, so it MIGHT pose a
                                    // problem when encrypting the attribute name.
                                    // To fix this, we will simply replace all the "/" with another
                                    // char ("*" in this case).
                                    // FIX - Geometric encryption
                                    // Changed the codec from Base64 to Hex. There should not be
                                    // any problem with this codec.
                                    String encAttribName = Hex.encodeHexString(bytesAttribEnc, true);
                                    encAttribName = encAttribName.replace("/", "_");
                                    attribEnc = attribParts[0] + "/" + attribParts[1] + "/" + encAttribName + "_enc";

                                    // Simple "encrypted" attribute names:
                                    // Attach the "_enc" prefix.
                                    //attribEnc = originalQualifAttribName + "_enc";
                                    */
                                    // FIX - Column names WILL NOT be encripted
                                    // This features encoutered problems with docker
                                    attribEnc = originalQualifAttribName + "_enc";
                                } else {
                                    // Otherwise, just let the attribute name
                                    // pass in plain text
                                    // In this case, the attribute was
                                    // identified but it is not protected.
                                    attribEnc = notProtected.apply(originalQualifAttribName);
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                                System.exit(1);
                            }
                            return attribEnc;
                        }));
        return mapping;
    }
}
