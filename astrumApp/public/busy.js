const wsURI = `ws://localhost:8000/`;
const ws = new WebSocket(wsURI);

window.addEventListener(ws.onmessage)