package eu.clarussecure.dataoperations.encryption.operators;

public class StringEquals extends Select {
    public StringEquals(String threshold) {
        this.threshold = threshold;
    }

    @Override
    public boolean select(String data) {
        // This is a simple String comparison, compare the strings
        return this.threshold.equals(data);
    }
}
