package eu.clarussecure.dataoperations.encryption.testing;

import eu.clarussecure.dataoperations.Criteria;
import eu.clarussecure.dataoperations.encryption.operators.Select;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Cloud {
    // Dommy implementation for a cloud
    // The implementation is a table, saving columns and rows.

    private List<String[]> data;
    private final String[] columns; // attributes

    public Cloud(String[] columns) {
        this.columns = columns;
        this.data = new ArrayList<>();
    }

    public void addRow(String[] row) {
        // It is assumed that the given arrays contains the columns in order!
        this.data.add(row);
    }

    public void addRows(String[][] rows) {
        // Each array will be added to the data
        this.data.addAll(Arrays.asList(rows));
    }

    public String[][] getRows(String[] protectedAttribNames, Criteria[] criteria) {
        // Select the columns regarding the required attribute names
        List<String[]> results = new ArrayList<>();
        List<String[]> filteredResults = new ArrayList<>();

        // First, parse the selection criteria and prepare the Select instances
        Map<String, List<Select>> selectorsSet = new HashMap<>();

        if (criteria == null) {
            // There is no criteria, use the Identity Function
            List<Select> selectors = selectorsSet.get("all");
            if (selectors == null) {
                selectors = new ArrayList<>();
                selectorsSet.put("all", selectors);
            }
            selectors.add(Select.getInstance("id", "")); // No threshold is required for the identity
        } else {
            // There are criteria. Build the selectors
            for (Criteria crit : criteria) {
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

        // TODO - Process the criteria to filter the data
        // IDEA - This could be done in this part of the code.
        for (String[] row : data) { // Select each row of the loaded data
            int p = 0; // column position in the results table
            String[] selectedRow = new String[protectedAttribNames.length]; // new result row
            for (int i = 0; i < columns.length; i++) { // for each stored column name

                for (String protectedAttribName : protectedAttribNames) { //for each requested column
                    if (columns[i].equals(protectedAttribName)) { // check if this is a requested column

                        // Copy the value on position i (data stored in the requested column) in the found row
                        // to the row i, column p on the results
                        selectedRow[p] = row[i];
                        p++; // move to the left on the results table
                        break;
                    }
                }
            }
            results.add(selectedRow);
        }

        // Apply the filters of the rows
        results.forEach((rowResult) -> {
            boolean selected = true; // to decide if this row should be included in the result or not
            for (int i = 0; i < rowResult.length; i++) {
                // We assume the attribute names are in the same order of the content
                // Get the selectors of this attribute
                List<Select> attributeSelectors = selectorsSet.get(protectedAttribNames[i]);
                // if no selectors were found, simply insert the identity
                if (attributeSelectors == null)
                    attributeSelectors = new ArrayList<>();
                // Do not forget the filters applied to "all";
                if (selectorsSet.get("all") != null) {
                    attributeSelectors.addAll(selectorsSet.get("all"));
                }
                // Evaluate each attribute selector
                for (Select selector : attributeSelectors) {
                    // Decide if the row should be selected or not
                    // NOTE - This line gives the "and" semantics to multiple criteria
                    selected = selected && selector.select(rowResult[i]);
                }
            }
            // Add the column only if all the selectors have passed
            if (selected) {
                filteredResults.add(rowResult);
            }
        });
        return filteredResults.toArray(new String[filteredResults.size()][]);
    }

    public String printCloudContents() {
        String ret = Arrays.deepToString(columns) + "\n";

        for (String[] row : data) {
            ret += Arrays.deepToString(row) + "\n";
        }
        return ret;
    }
}
