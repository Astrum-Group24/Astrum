const wsURI = `ws://localhost:8000/`;
const ws = new WebSocket(wsURI);


ws.onopen = function(onopen) {
    ws.send(`runScan`);

    ws.addEventListener('message', function(event) {
        for(i = 0; i < 1; i++) {

            if (event.data === `scanComplete`) {
                
                console.log(`scanComplete received`);
                
                window.location = '/showResults';

                ws.send(`closeWS`)

                ws.readyState()

            }        
        }
    })

}
