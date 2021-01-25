const fs = require("fs");
const { encode } = require("querystring");

const pathToReports = `./reports/2021-01-19-05-52-50/html`;
let portsArray = [];

readPorts(pathToReports);


// function to read ports from .json files
function readPorts(pathToReports) {

    const pathToJSON = `${pathToReports.substring(0, pathToReports.length - 5)}/json`;
    console.log(`***pathtoJSON value:`, pathToJSON);

    const filenames = fs.readdirSync(pathToJSON);
    console.log(`***JSON filenames value:`, filenames);


    // loop thru filenames
    for (i = 1; i < filenames.length; i++) {
        // read into server as a string
        const reportString = fs.readFileSync(`${pathToJSON}/${filenames[i]}`, 'utf8');
        console.log(`***reportString value: ${reportString}`);

        // parse string into javascript object
        const reportObject = JSON.parse(reportString);
        const portsString = JSON.stringify(reportObject.machine.ports);
        const numbersArray = portsString.match(/\d+/g);
        portsArray.push(numbersArray);
        console.log(portsString);
        console.log(numbersArray);
        console.log(portsArray);


    };
};