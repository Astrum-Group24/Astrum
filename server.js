
//include file system and http modules
var http = require("http"); 
var fs = require("fs");
var os = require("os");

//Creating the server
var server = http.createServer(function(req, res){
    
    //when top-level directory is requested    
    if(req.url === "/") {
        
        //show index.html
        fs.readFile("./index.html","UTF-8",function(err, body){
           
        //respond OK in the header(200), notify content is of type html/text, and end.
        res.writeHead(200, {"Content-Type":"text/html"}); 
        res.end(body);
        });
    }

    //when the link is clicked (./public/rando.log)
    else if(req.url.match("/public/rando.log")){
        
        //show file contents
        fs.readFile("./rawlogs/2020", "UTF-8",function(err, data){
        
        //respond OK in the header(200), notify content is of type text/plain, and end
        res.writeHead(200, {"Content-Type":"text/plain"});
        res.end(data);
    });
    }

    //contingency when things are broken
    else {
        res.writeHead(404, {"Content-Type":"text/plain"});
        res.end(`404 File Not Found at ${req.url}`); 
    }
});

//tell the server to listen for requests on port 3000, and log message on console
server.listen(3000); 
console.log("Server listening on port 3000"); 