"use strict";

require("dotenv").config();

const connectMongoDB = require("./database");

async function startServer() {
    try {
        await connectMongoDB();
        console.log("MongoDB connected successfully.");
        const { start } = require("./app");
        await start();
    } catch (error) {
        console.error("SERVER STARTUP FAILED");
        console.error(error);
        process.exit(1);
    }
}

startServer();
