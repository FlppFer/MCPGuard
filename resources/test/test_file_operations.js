// Vulnerable: fs operations
const fs = require('fs');

function readSensitive() {
    fs.readFileSync('/etc/passwd');
    fs.writeFileSync('/tmp/output.txt', data);
    fs.unlinkSync('/tmp/secret.txt');
    fs.rmdirSync('/tmp/dir');
}

// Vulnerable: fs.promises
async function asyncOps() {
    await fs.promises.readFile('/etc/shadow');
    await fs.promises.writeFile('/tmp/data.txt', 'payload');
    await fs.promises.unlink('/tmp/remove.txt');
}

// Vulnerable: path traversal
function traversal(userInput) {
    fs.readFileSync('../../../etc/passwd');
    fs.readFileSync(userInput + '/../secret');
}

// Vulnerable: chmod/chown
function permChange() {
    fs.chmodSync('/tmp/file', 0o777);
    fs.chownSync('/tmp/file', 0, 0);
}

// Safe: normal variable assignment
const x = 42;
const name = "safe";
