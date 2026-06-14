'use strict';

const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { exec } = require('child_process');
const { getProcesses, getSystemStats } = require('./core/processManager');

let mainWindow = null;
let processInterval = null;
let statsInterval = null;
let isRefreshing = false;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1300,
    height: 820,
    minWidth: 1000,
    minHeight: 620,
    frame: false,
    backgroundColor: '#0d1117',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile('index.html');

  mainWindow.on('closed', () => { mainWindow = null; });

  // Dev tools in dev mode
  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  }
}

async function pushProcessData() {
  if (!mainWindow || isRefreshing) return;
  isRefreshing = true;
  try {
    const processes = await getProcesses();
    if (mainWindow) mainWindow.webContents.send('process-update', processes);
  } catch (e) {
    console.error('Process refresh error:', e);
  } finally {
    isRefreshing = false;
  }
}

async function pushStatsData() {
  if (!mainWindow) return;
  try {
    const stats = await getSystemStats();
    if (mainWindow) mainWindow.webContents.send('stats-update', stats);
  } catch (e) {
    console.error('Stats refresh error:', e);
  }
}

function startRefreshCycles() {
  // Initial load
  pushStatsData();
  setTimeout(pushProcessData, 500);

  // Stats: every second
  statsInterval = setInterval(pushStatsData, 1500);

  // Processes: every 4 seconds
  processInterval = setInterval(pushProcessData, 4000);
}

// IPC handlers
ipcMain.handle('force-refresh', async () => {
  await pushProcessData();
  return true;
});

ipcMain.handle('is-admin', () => {
  return new Promise((resolve) => {
    // 'net session' fails for non-admin users — reliable Windows admin check
    exec('net session', (err) => resolve(!err));
  });
});

ipcMain.handle('kill-process', async (_, pid) => {
  const safePid = parseInt(pid, 10);
  if (!Number.isInteger(safePid) || safePid <= 4) {
    return { success: false, error: 'Cannot kill protected system process.' };
  }
  return new Promise((resolve) => {
    exec(`taskkill /F /PID ${safePid}`, (err, stdout, stderr) => {
      if (err) resolve({ success: false, error: stderr || err.message });
      else resolve({ success: true });
    });
  });
});

ipcMain.handle('suspend-process', async (_, pid) => {
  const safePid = parseInt(pid, 10);
  if (!Number.isInteger(safePid) || safePid <= 4) {
    return { success: false, error: 'Cannot suspend protected system process.' };
  }
  return new Promise((resolve) => {
    exec(`pssuspend ${safePid}`, (err) => {
      if (err) {
        resolve({ success: false, error: 'Suspend requires Sysinternals PsSuspend. Download at: learn.microsoft.com/sysinternals' });
      } else {
        resolve({ success: true });
      }
    });
  });
});

ipcMain.handle('resume-process', async (_, pid) => {
  const safePid = parseInt(pid, 10);
  if (!Number.isInteger(safePid) || safePid <= 4) {
    return { success: false, error: 'Cannot resume protected system process.' };
  }
  return new Promise((resolve) => {
    exec(`pssuspend -r ${safePid}`, (err) => {
      if (err) resolve({ success: false, error: 'Resume requires Sysinternals PsSuspend.' });
      else resolve({ success: true });
    });
  });
});

ipcMain.handle('open-file-location', async (_, filePath) => {
  if (!filePath) return { success: false, error: 'No path available' };
  try {
    shell.showItemInFolder(filePath);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('search-online', async (_, query) => {
  try {
    await shell.openExternal(`https://www.google.com/search?q=${encodeURIComponent(query + ' process safe')}`);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.on('window-minimize', () => mainWindow?.minimize());
ipcMain.on('window-maximize', () => {
  if (mainWindow?.isMaximized()) mainWindow.unmaximize();
  else mainWindow?.maximize();
});
ipcMain.on('window-close', () => mainWindow?.close());

app.whenReady().then(() => {
  createWindow();
  startRefreshCycles();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  clearInterval(processInterval);
  clearInterval(statsInterval);
  if (process.platform !== 'darwin') app.quit();
});
