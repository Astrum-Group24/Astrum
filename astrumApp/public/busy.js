const wsURI = `ws://localhost:8000/`;
const ws = new WebSocket(wsURI);

ws.onopen = function(onopen) {
    ws.send(`runScan`);

    ws.addEventListener('message', function(event) {
        if (event.data === `scanComplete`) {
            console.log(`scanComplete received`)
            
            fetch("https://www.google.com")
        }
    })
}

