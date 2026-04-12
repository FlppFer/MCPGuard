// Vulnerable: child_process.exec
const { exec, execSync } = require('child_process');

function runCommand(userInput) {
    exec('ls -la ' + userInput);
    execSync(`rm -rf ${userInput}`);
}

// Vulnerable: eval
function evaluate(code) {
    eval(code);
}

// Vulnerable: Function constructor
const fn = new Function('a', 'return a + 1');

// Vulnerable: require child_process with dynamic arg
const cp = require('child_process');
cp.exec(userInput);

// Safe: no dangerous calls
function safeFunction(a, b) {
    return a + b;
}

// Safe: console.log
console.log("hello world");
