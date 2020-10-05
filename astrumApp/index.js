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

//Run script when post is rec'd from root
app.post("/", (req, res) => {
    
    //Proof-of-concept statement, creates a testFile in /home/brett/Documents/
    shell.exec('touch /home/brett/Documents/testFile');

});






/**
 * Server Activation
 */

app.listen(port, () => {
    console.log(`Listening to requests on http://localhost:${port}`);
});
