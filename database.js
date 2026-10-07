"use strict";

const mongoose = require("mongoose");

async function connectMongoDB() {
    const uri = process.env.MONGODB_URI;
    if (typeof uri !== "string" || !uri.trim()) {
        throw new Error("MONGODB_URI must be configured before server startup.");
    }

    mongoose.connection.on("error", error => {
        console.error("MongoDB connection error:", error.name);
    });
    await mongoose.connect(uri);
    console.log("MongoDB connected.");
}

module.exports = connectMongoDB;
