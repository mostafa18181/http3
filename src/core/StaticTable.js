// StaticTable.js

// تعریف جدول استاتیک QPACK
const staticTable = [
    { index: 0, key: ':authority', value: '' },
    { index: 1, key: ':path', value: '/' },
    { index: 2, key: ':method', value: 'GET' },
    { index: 3, key: ':method', value: 'POST' },
    { index: 4, key: ':scheme', value: 'http' },
    { index: 5, key: ':scheme', value: 'https' },
    { index: 6, key: ':status', value: '200' },
    { index: 7, key: ':status', value: '404' },
    { index: 8, key: ':status', value: '500' },
    { index: 9, key: 'accept', value: '*/*' },
    { index: 10, key: 'accept-encoding', value: 'gzip, deflate, br' },
    { index: 11, key: 'content-type', value: 'application/json' },
    { index: 12, key: 'user-agent', value: '' },
    { index: 13, key: 'cache-control', value: 'no-cache' },
];

// خروجی جدول به صورت ماژول
module.exports = staticTable;
