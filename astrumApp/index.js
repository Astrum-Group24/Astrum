// index.js

/**
 * Required External Modules
 */

const express = require("express");
const path = require("path");
const shell = require("shelljs");






/**
 * App Variables
 */

const app = express();
const port = process.env.PORT || "8000";






/**
 *  App Configuration
 */

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");
app.use(express.static(path.join(__dirname, "public")));





/**
 * Routes Definitions
 */

//Show index.pug when navigting to root address
 app.get("/", (req, res) => {
    res.render("index", { title: "Home"});
});

//**IMCOMPLETE** NEEDS PARAMS FOR SCRIPT. Run script when post is rec'd from root 
app.post("/", (req, res) => {
    shell.exec('bash Astrum.sh ')
});






/**
 * Server Activation
 */

app.listen(port, () => {
    console.log(`Listening to requests on http://localhost:${port}`);
});

