const fs = require("fs");
const { encode } = require("querystring");

const pathToReports = `./reports/2021-01-19-05-52-50/html`;
let allPortsArray = [];

readPorts(pathToReports);


// function to read ports from .json files
function readPorts(pathToReports) {

    const pathToJSON = `${pathToReports.substring(0, pathToReports.length - 5)}/json`;
    console.log(`***pathtoJSON value:`, pathToJSON);

    const filenames = fs.readdirSync(pathToJSON);
    console.log(`***JSON filenames value:`, filenames);


    // loop thru filenames
    for (i = 1; i < filenames.length; i++) {
        console.log(`***i = ${i}`);
        // read into server as a string
        const reportString = fs.readFileSync(`${pathToJSON}/${filenames[i]}`, 'utf8');
        console.log(`***reportString value: ${reportString}`);

        // parse string into javascript object
        const reportObject = JSON.parse(reportString);
        
        //check if port property exists
        if (reportObject.machine.hasOwnProperty("ports")) {
            
            // change ports object to string
            const portsString = JSON.stringify(reportObject.machine.ports);
           
            // match and extract found numbers to an array 
            const numbersArray = portsString.match(/\d+/g);
            
            console.log(portsString);
            console.log(numbersArray);
            
            // add newly found ports to the existing ones
            allPortsArray = allPortsArray.concat(numbersArray);
        }


        console.log(allPortsArray);


    };
    // using set() constructor fn to remove repeated elements
    const uniquePorts = new Set(allPortsArray);
    
    // using spread operator to map values to an array
    const uniquePortsArray = [...uniquePorts];
    console.log(uniquePortsArray);
    
    
    return uniquePortsArray;
};