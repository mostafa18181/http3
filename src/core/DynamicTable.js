class DynamicTable {
    constructor() {
        this.entries = []; // Array to store key-value pairs
    }

    add({ key, value }) {
        // Check if the key-value pair already exists
        const existingIndex = this.entries.findIndex(entry => entry.key === key && entry.value === value);
        if (existingIndex !== -1) {
            return existingIndex;// If it exists, return its index
        }

        // Add a new key-value pair
        this.entries.push({ key, value });
        const newIndex = this.entries.length - 1;  // New index
        return newIndex; // Return the new index
    }

    get(index) {
        return this.entries[index];  // Return the value at the given index
    }
}

module.exports = DynamicTable;
