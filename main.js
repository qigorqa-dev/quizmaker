const { app, BrowserWindow } = require('electron');
const path = require('path');
require('./server'); // start API

function createWindow () {
  const win = new BrowserWindow({
    width: 1120, height: 840,
    webPreferences: { preload: path.join(__dirname, 'preload.js') }
  });
  win.loadFile(path.join(__dirname, 'web', 'index.html'));
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
