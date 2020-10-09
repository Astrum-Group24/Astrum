// index.js

/**
 * Required External Modules
 */

const express = require("express");
const path = require("path");
const shell = require("shelljs");
const fs = require("fs");






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

//code to make html forms work
var bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({ extended: false }));


/**
 * Routes Definitions
 */

//Show index.pug when navigting to root address
 app.get("/", (req, res) => {
    res.render("index", { title: "Home"});
    res.end();
});

//Run script when post is rec'd from root
app.post("/", (req, res) => {
    var commandString
    const dir = './astrumApp/reports/html/'

    //take values and create complete command for Astrum script

    commandString = 'bash /home/astrum/Main/Astrum.sh -s ' + req.body.speed + ' -h ' + req.body.host + ' -u ' + req.body.username + ' -p ' + req.body.password;
    
    //execute command
    shell.exec(commandString);

    //Count HTML files in ../astrumApp/reports/html/ to determine number of links to make
    fs.readdir(dir, (err, files) => {
     console.log(files.length);
    });

    res.render("index", { title: "Home"});

    res.end();
});






/**
 * Server Activation
 */

app.listen(port, () => {
    console.log(`Listening to requests on http://localhost:${port}`);
});
