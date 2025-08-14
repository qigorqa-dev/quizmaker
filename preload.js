const { contextBridge } = require('electron');
contextBridge.exposeInMainWorld('env', { API_PORT: 38216 });
