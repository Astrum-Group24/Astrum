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








/**
 *  App Configuration
 */

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname, "reports/html")));

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



//Run script when post is rec'd from root and send to results page
app.post("/", (req, res) => {
    //hardcoded time for development purposes
    var timeRan = '2020-10-29-03-01';
    
    //take values and create complete command for Astrum script
    var commandString = 'bash /home/astrum/Main/Astrum.sh -s ' + req.body.speed + ' -h ' + req.body.host + ' -u ' + req.body.username + ' -p ' + req.body.password;
    var pathToReports = './reports/' + timeRan + '/html';
  
    runScript(commandString);

    readFolder(pathToReports);
    
    renderPage();
    

    //Iterate thru filenames to create arrays for links and link labels
    function readFolder(pathValue) {

        //variable & method for reading records filenames into an array
        filenames = fs.readdirSync(pathValue);

        //variable and method to remove file extension for link labels
        ipAddresses = filenames.map(removeExtension);

        //method to sort labels ascending
        ipAddresses.sort((a, b) => {
            const num1 = Number(a.split(".").map((num) => (`000${num}`).slice(-3) ).join(""));
            const num2 = Number(b.split(".").map((num) => (`000${num}`).slice(-3) ).join(""));
            return num1-num2;
        });

        //add .html to ips to create links
        ipAddressesLink = ipAddresses.map(addExtension);


    }

    //function to remove last five characters of each element
    function removeExtension(value) {

        return value.substring(0, value.length - 5);

    };

    //function that adds .html to the end of an item
    function addExtension(value) {

        return value + '.html'

    }

    //function to render the page
    function renderPage() {

        res.render("results", {ipAddressesLink, ipAddresses, title: 'Results'});

    }

    //function to execute command in shell
    function runScript(value) {

        //shell.exec(value);

    }


    //show array on console for debugging
    console.log("type of record is: " + typeof ipAddressesLink);
    console.log(ipAddressesLink);
    console.log(ipAddresses);

    res.end();
});

//send html files when reports are accessed
app.get('/reports/html', (req, res) => {

    console.log(req.originalUrl);
    res.sendFile(req.originalUrl);
    res.end();
});


/**
 * Server Activation
 */

app.listen(port, () => {
    console.log(`Listening to requests on http://localhost:${port}`);
});
