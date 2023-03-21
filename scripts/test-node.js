const fs = require('fs');
const path = require('path');
const target = path.resolve(__dirname, '..', 'test', 'setup', 'Weblgcy.js');

try {
    fs.unlinkSync(target);
} catch(ex) {}

fs.copyFileSync(
    path.resolve(__dirname, '..', 'test', 'setup', 'node.js'),
    target
);