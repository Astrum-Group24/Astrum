const fs = require("fs");
const { encode } = require("querystring");

const pathToReports = `./reports/2021-01-19-05-52-50/html`;

readPorts(pathToReports);


// function to read ports from .json files
function readPorts(pathToReports) {

    const pathToJSON = `${pathToReports.substring(0, pathToReports.length - 5)}/json`;
    console.log(`***pathtoJSON value:`, pathToJSON);

    const filenames = fs.readdirSync(pathToJSON);
    console.log(`***JSON filenames value:`, filenames);


    // loop thru filenames
    for (i = 1; i < 2; i++) {
        // read into server as a string
        const reportString = fs.readFileSync(`${pathToJSON}/${filenames[i]}`, 'utf8');
        console.log(reportString);

        // parse string into javascript object
        const reportObject = JSON.parse(reportString);
        console.log(reportObject.machine);
    };
};