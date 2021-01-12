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
var ipAddresses;
var ipAddressesLink;
var filenames;
var pathToReports







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
    res.render("index", { title: "Home" });
    res.end();
});



//Run script when post is rec'd from root and send to results page
app.post("/", (req, res) => {

    //take values and create complete command for Scan.sh script
    var commandString = 'source ./Scan.sh -s ' + req.body.speed + ' -h ' + req.body.host + ' -u ' + req.body.username + ' -p ' + req.body.password;

    runScript(commandString);

    readFolder(findNewestFolder('./reports'));

    renderPage();


    //function that adds path and extension to IPs to create links
    function addLinkElements(value) {

        //return pathToReports.substring(1) + '/' + value + '.html'
        return `${value}.html`

    }


    //find newest folder, used to find the most recent (and likely most-relevant) reports folder
    function findNewestFolder(rootPath) {

        directoryEntries = fs.readdirSync(rootPath);

        //append root and child folders
        pathToReports = `./reports/${directoryEntries[(directoryEntries.length - 1)]}/html`;

        //alternative path for devlopment and debug
        //pathToReports = `./reports/2020-11-04-04-43-40/html`;

        //makes files in path available
        app.use(express.static(path.join(__dirname, pathToReports)));

        //return latesst entry
        return pathToReports;

    }


    //Iterate thru filenames to create arrays for links and link labels
    function readFolder(pathValue) {

        //variable & method for reading records filenames into an array
        filenames = fs.readdirSync(pathValue);

        //variable and method to remove file extension for link labels
        ipAddresses = filenames.map(removeExtension);

        //metdo/function to sort labels ascending
        ipAddresses.sort((a, b) => {
            const num1 = Number(a.split(".").map((num) => (`000${num}`).slice(-3)).join(""));
            const num2 = Number(b.split(".").map((num) => (`000${num}`).slice(-3)).join(""));
            return num1 - num2;
        });

        //add elements and extension to ips to create links
        ipAddressesLink = ipAddresses.map(addLinkElements);

        console.log(`ipAddressesLink value:`);
        console.log(ipAddressesLink);


    }

    //function to remove last five characters of each element
    function removeExtension(value) {

        return value.substring(0, value.length - 5);

    };

    //function to render the page
    function renderPage() {

        res.render("results", { ipAddressesLink, ipAddresses, title: 'Results' });

    }

    res.end();
});


//send html files when reports are accessed via 'multiple' form & 'show report' button
app.post('/reports', (req, res) => {
    //create report path
    const reportPath = `${pathToReports.substring(1)}/${req.body.host}.html`;

    //console.log(reportPath)

    //send file to browser
    res.sendFile(path.join(__dirname + reportPath));
});

//generate script when button is clicked
app.post('/generate', (req, res) => {

    const commandString = `source ./Resolution.sh -f ${req.body.host} -w ${req.body.whitelist}`;

    runScript(commandString);

});

//function to execute command in shell
function runScript(value) {

    shell.exec(value);

}

/**
 * Server Activation
 */

app.listen(port, () => {
    console.log(`Listening to requests on http://localhost:${port}`);
});
