package eu.clarussecure.dataoperations.encryption.testing;

import eu.clarussecure.dataoperations.Criteria;
import eu.clarussecure.dataoperations.DataOperation;
import eu.clarussecure.dataoperations.DataOperationCommand;
import eu.clarussecure.dataoperations.DataOperationResponse;
import eu.clarussecure.dataoperations.DataOperationResult;
import eu.clarussecure.dataoperations.encryption.EncryptionModule;
import eu.clarussecure.dataoperations.encryption.EncryptionResult;
import java.io.File;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class Demo {
    public final static String POLICY_FILENAME = "/Users/diego/Dropbox/Montimage/CLARUS//sec-pol-examples/enc-pol.xml";
    public final static String DATA_FILENAME = "/Users/diego/Dropbox/Montimage/CLARUS/sec-pol-examples/meuse2.txt";

    public static void main(String[] args) throws IOException, SAXException, ParserConfigurationException {
        // Read the data from the file
        String[] attributes = readColumnNames(DATA_FILENAME);
        String[][] data = readData(DATA_FILENAME);

        // Initialize the "cloud" to execute the commands
        Cloud cloud = null;
        Cloud untouchedCloud = new Cloud(attributes);
        untouchedCloud.addRows(data);

        // Print the untouched cloud
        System.out.println("*****************ORIGINAL*******************");
        System.out.print(untouchedCloud.printCloudContents());
        System.out.println("********************************************");

        // Parse the XML security policy
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document policy = db.parse(new File(POLICY_FILENAME));

        // Instantiate the Clarus Encryption Module
        DataOperation encryption = new EncryptionModule(policy);
        //DataOperation encryption = new EncryptionModule(null);

        // First "POST" to the cloud
        List<DataOperationCommand> commandsPost = encryption.post(attributes, data);
        // Create a cloud object with the protected Attribute Names
        cloud = new Cloud(commandsPost.get(0).getProtectedAttributeNames());

        // Query the cloud
        for (DataOperationCommand command : commandsPost) {
            cloud.addRows(command.getProtectedContents());
        }

        // Show the content of the cloud
        System.out.println("****************ENCRYPTED*******************");
        System.out.print(cloud.printCloudContents());
        System.out.println("********************************************");

        // Insert a new row into the cloud
        String[][] append = { { "500", "1.800000000000000", "25.000000000000000", "97.000000000000000",
                "251.000000000000000", "9.073000000000000", "0.228123000000000", "9.000000000000000", "1", "1", "0",
                "Ag", "300.000000000000000", "0101000020E61000000000000040190641000000009C531441" } };

        List<DataOperationCommand> commandsPost2 = encryption.post(attributes, append);

        // Query the cloud
        for (DataOperationCommand command : commandsPost2) {
            cloud.addRow(command.getProtectedContents()[0]);
        }

        // Show the content of the cloud
        System.out.println("***************ENCRYPTED-2******************");
        System.out.print(cloud.printCloudContents());
        System.out.println("********************************************");

        // Retrieve the data from the cloud
        // CASE 1: no criteria = all the data
        List<DataOperationCommand> commandsGet = encryption.get(attributes, null);

        // Query the cloud
        List<String[][]> results = new ArrayList<>();
        for (DataOperationCommand command : commandsGet) {
            // Get all the columns from the database
            String[][] partialResult = cloud.getRows(command.getProtectedAttributeNames(), command.getCriteria());
            results.add(partialResult);
        }

        // Recover the original values
        List<DataOperationResult> r = encryption.get(commandsGet, results);
        // We assume the inbound get does not trigger another call to the cloud, so we cast the result.
        EncryptionResult response = (EncryptionResult) r.get(0);

        // Show the content of the response, using an auxiliary cloud
        Cloud aux = new Cloud(response.getDecryptedAttributeNames());
        aux.addRows(response.getDecryptedContent());
        System.out.println("*****************DECRYPTED******************");
        System.out.print(aux.printCloudContents());
        System.out.println("********************************************");

        // CASE 2: select some columns
        String[] someColumns = { "meuseDB/meuse/gid", "meuseDB/meuse/copper", "meuseDB/meuse/lead" };
        commandsGet = encryption.get(someColumns, null);

        // Query the cloud
        results = new ArrayList<>();
        for (DataOperationCommand command : commandsGet) {
            // Get all the columns from the database
            String[][] partialResult = cloud.getRows(command.getProtectedAttributeNames(), command.getCriteria());
            results.add(partialResult);
        }

        // Recover the original values
        r = encryption.get(commandsGet, results);
        // We assume the inbound get does not trigger another call to the cloud, so we cast the result.
        response = (EncryptionResult) r.get(0);

        // Show the content of the response, using an auxiliary cloud
        aux = new Cloud(response.getDecryptedAttributeNames());
        aux.addRows(response.getDecryptedContent());
        System.out.println("****************DECRYPTED-2*****************");
        System.out.print(aux.printCloudContents());
        System.out.println("********************************************");

        // CASE 3: Find a single record with a Criterion (using entry ID)
        Criteria crit = new Criteria("meuseDB/meuse/gid", "=", "5");
        commandsGet = encryption.get(attributes, new Criteria[] { crit });

        // Query the cloud
        results = new ArrayList<>();
        for (DataOperationCommand command : commandsGet) {
            // Get all the columns from the database
            String[][] partialResult = cloud.getRows(command.getProtectedAttributeNames(), command.getCriteria());
            results.add(partialResult);
        }

        // Recover the original values
        r = encryption.get(commandsGet, results);
        // We assume the inbound get does not trigger another call to the cloud, so we cast the result.
        response = (EncryptionResult) r.get(0);

        // Show the content of the response, using an auxiliary cloud
        aux = new Cloud(response.getDecryptedAttributeNames());
        aux.addRows(response.getDecryptedContent());
        System.out.println("****************DECRYPTED-3*****************");
        System.out.print(aux.printCloudContents());
        System.out.println("********************************************");

        // CASE 3: Find records with multiple criteria in different columns
        // NOTE - At the moment, using multiple criteria has an "and" semantics
        crit = new Criteria("meuseDB/meuse/gid", ">=", "20");
        Criteria crit2 = new Criteria("meuseDB/meuse/lead", ">=", "500");
        commandsGet = encryption.get(attributes, new Criteria[] { crit, crit2 });

        // Query the cloud
        results = new ArrayList<>();
        for (DataOperationCommand command : commandsGet) {
            // Get all the columns from the database
            String[][] partialResult = cloud.getRows(command.getProtectedAttributeNames(), command.getCriteria());
            results.add(partialResult);
        }

        // Recover the original values
        r = encryption.get(commandsGet, results);
        // We assume the inbound get does not trigger another call to the cloud, so we cast the result.
        response = (EncryptionResult) r.get(0);

        // Show the content of the response, using an auxiliary cloud
        aux = new Cloud(response.getDecryptedAttributeNames());
        aux.addRows(response.getDecryptedContent());
        System.out.println("****************DECRYPTED-4*****************");
        System.out.print(aux.printCloudContents());
        System.out.println("********************************************");
    }

    private static String[] readColumnNames(String filename) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(filename));

        String line = br.readLine();
        br.close();

        return line.split(",");
    }

    private static String[][] readData(String filename) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(filename));

        br.readLine(); // discard first line: column names

        String line;
        Set<String[]> data = new HashSet<>();
        int records = 0, columns = 1;

        while ((line = br.readLine()) != null) {
            data.add(line.split(","));
            records++;
            columns = line.split(",").length;
        }

        return data.toArray(new String[columns][records]);
    }
}
