// index.js

/**
 * Required External Modules
 */

const express = require("express");
const path = require("path");

/**
 * App Variables
 */

const app = express();
const port = process.env.PORT || "3000";

/**
 *  App Configuration
 */

/**
 * Routes Definitions
 */

app.get("/", (req, res) => {
    res.status(200).send("Astrum Network Analysis");
});

/**
 * Server Activation
 */

app.listen(port, () => {
    console.log(`Listening to requests on http://localhost:${port}`);
});

