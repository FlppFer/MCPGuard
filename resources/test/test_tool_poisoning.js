// Vulnerable: dynamic tool description in MCP SDK
const { Server } = require('@modelcontextprotocol/sdk');

const server = new Server();

// Vulnerable: server.tool with dynamic description
server.tool(userInput, dynamicDescription, async (params) => {
    return params;
});

// Vulnerable: overwriting description after registration
const tool = { name: "myTool", description: "safe" };
tool.description = userControlledString;

// Vulnerable: prototype pollution
const obj = {};
obj.__proto__.admin = true;
obj.constructor.prototype.isAdmin = true;

// Vulnerable: Object.assign with user input
Object.assign(target, userInput);

// Safe: static tool registration
server.tool("calculator", "A simple calculator tool", async (params) => {
    return { result: params.a + params.b };
});

// Safe: normal object
const config = { port: 3000, host: "localhost" };
