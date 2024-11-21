
    const DynamicTable = require('./DynamicTable');
 
class QPACK {
    constructor() {
        this.dynamicTable = new DynamicTable();  // Create a dynamic table
    }

    compressHeaders(headers) {
        return headers.map(header => {
            if (header.type === 'literal') {
                const { key, value } = header.header || {};
                if (!key || !value) {
                    throw new Error('Invalid literal header format for compression.');
                }
    
                // Add to the client's dynamic table
                const index = this.dynamicTable.add({ key, value });
                console.log("Added to dynamic table (client):", { key, value, index });
    
                return { type: 'literal', header: { key, value } }; // Return header as literal
            } else if (header.type === 'indexed') {
                const { index, table } = header;
                if (typeof index !== 'number' || !table) {
                    throw new Error('Invalid indexed header format for compression.');
                }
                return { type: 'indexed', index, table };  // Return index
            } else {
                throw new Error(`Unsupported header type: ${header.type}`);
            }
        });
    }
    decompressHeaders(headers) {
        return headers.map(header => {
            if (header.type === 'indexed') {
                console.log("Fetching from dynamic table (server) with index:", header.index);
                const entry = this.dynamicTable.get(header.index);
                if (!entry) {
                    throw new Error(`Invalid index ${header.index} in dynamic table.`);
                }
                return entry; // Return value from the server's dynamic table
            } else if (header.type === 'literal') {
                const { key, value } = header.header || {};
                if (!key || !value) {
                    throw new Error('Invalid literal header format.');
                }
    
                // Add a new value to the server's dynamic table
                const index = this.dynamicTable.add({ key, value });
                console.log("Added to dynamic table (server):", { key, value, index });
    
                return { key, value };  // Return header as key-value pair
            } else {
                throw new Error(`Unsupported header type: ${header.type}`);
            }
        });
    }
        
}

module.exports = QPACK;
