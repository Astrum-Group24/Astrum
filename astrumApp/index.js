// index.js

/**
 * Required External Modules
 */

const express = require("express");
const path = require("path");
const shell = require("shelljs");
const fs = require("fs");
const WebSocket = require("ws");


/**
 * App Variables
 */

const app = express();
const port = 8000;
let ipAddresses;
let ipAddressesLink;
let filenames;
let pathToReports;
let allPortsArray = [];
let commandString;


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
    console.log(`Start: ${Date().toLocaleString('en-US')}`);

    //take values and create complete command for Scan.sh script
    commandString = `source ./Scan.sh -s ${req.body.scanType} -h ${req.body.host} -u ${req.body.username} -p ${req.body.password}`;
    console.log(commandString);
    console.log(`${req.body.scanType}`);

    //render the busy page
    res.render("busy", {title: "Scanning"})
    
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

    console.log(commandString);

    runScript(commandString);

    res.download(path.join(__dirname + `/resolution/${req.body.host}/ComplianceScript.sh`), `${req.body.host}_script.sh`);

});

//function to execute command in shell
function runScript(value) {

    shell.exec(value);

}

function runScan(commandString) {
    runScript(commandString);

    readFolder(findNewestFolder('./reports'));

    //renderPage();

    console.log(`End: ${Date().toLocaleString('en-US')}`);




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
        filenames.splice(0, 1);
        console.log(`***filenames value:`);
        console.log(filenames);

        //variable and method to remove file extension for link labels
        ipAddresses = filenames.map(removeExtension);
        console.log(`***ipAddresses value:`);
        console.log(ipAddresses);

        //metdo/function to sort labels ascending
        ipAddresses.sort((a, b) => {
            const num1 = Number(a.split(".").map((num) => (`000${num}`).slice(-3)).join(""));
            const num2 = Number(b.split(".").map((num) => (`000${num}`).slice(-3)).join(""));
            return num1 - num2;
        });

        //add elements and extension to ips to create links
        ipAddressesLink = ipAddresses.map(addLinkElements);

        console.log(`***ipAddressesLink value:`);
        console.log(ipAddressesLink);


    }



    //function to remove last five characters of each element
    function removeExtension(value) {

        return value.substring(0, value.length - 5);

    };


}

app.get('/showResults', (req, res) => { 

    renderPage();

    // function to read ports from .json files
    function readPorts(pathToReports) {

        const pathToJSON = `${pathToReports.substring(0, pathToReports.length - 5)}/json`;

        const filenames = fs.readdirSync(pathToJSON);


        // loop thru filenames
        for (i = 1; i < filenames.length; i++) {
            // read into server as a string
            const reportString = fs.readFileSync(`${pathToJSON}/${filenames[i]}`, 'utf8');

            // try/catch statement to handle invalid jsons
            try {
                // parse string into javascript object
                const reportObject = JSON.parse(reportString);

                //check if port property exists
                if (reportObject.machine.hasOwnProperty("ports")) {

                    // change ports object to string
                    const portsString = JSON.stringify(reportObject.machine.ports);

                    // match and extract found numbers to an array 
                    const numbersArray = portsString.match(/\d+/g);

                    // add newly found ports to the existing ones by concatenating the arrays
                    allPortsArray = allPortsArray.concat(numbersArray);
                }
            }
            catch (err) {
                console.log(`Error reading/parsing ${reportString}. Likely invalid input.`);
            }

        };
        // using set() constructor fn to remove repeated elements
        const uniquePorts = new Set(allPortsArray);

        // using spread operator to map values to an array
        const uniquePortsArray = [...uniquePorts];

        return uniquePortsArray;
    };

    //function to render the page
    function renderPage() {

        const ports = readPorts(pathToReports);
        res.render("results", { ipAddressesLink, ipAddresses, ports, title: 'Results' });

    }

    res.end();

})

/**
 * Server Activation
 */

const server = app.listen(port, console.log(`Listening to requests on http://localhost:${port}`))

const wsServer = new WebSocket.Server({ server })

wsServer.on('connection', function (ws) {
    console.log(`WebSocket ready on ws://localhost:${port}`);
    ws.send('Hello from Astrum WebSocket Server');
    ws.on('message', function (data) {
        if (data === `runScan`) {
            runScan(commandString);
            ws.send(`scanComplete`);
        } else if (data === `closeWS`) {
            ws.send(`allDone`);
            ws.close();
        }
    })
})