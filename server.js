"use strict";

require("dotenv").config();

const connectMongoDB = require("./database");

connectMongoDB()
    .then(() => {
        require("./app");
    })
    .catch(error => {
        if (error.message === "MONGODB_URI must be configured before server startup.") {
            console.error(error.message);
        } else {
            console.error("MongoDB connection failed; server was not started.", error.name);
        }
        process.exitCode = 1;
    });
