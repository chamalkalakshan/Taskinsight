'use strict';

const { app, BrowserWindow, ipcMain, Tray, Menu, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const { getProcesses, getSystemStats } = require('./core/processManager');

let mainWindow = null;
let tray = null;
let isQuitting = false;
let processInterval = null;
let statsInterval = null;
let isRefreshing = false;

function createTray() {
  const iconPath = path.join(__dirname, 'assets', 'tray.png');
  tray = new Tray(iconPath);
  tray.setToolTip('TaskInsight');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Show TaskInsight', click: () => { mainWindow?.show(); mainWindow?.focus(); } },
    { type: 'separator' },
    { label: 'Quit TaskInsight', click: () => { isQuitting = true; app.quit(); } },
  ]));
  tray.on('double-click', () => { mainWindow?.show(); mainWindow?.focus(); });
}

function createWindow() {
  const startHidden = app.getLoginItemSettings().wasOpenedAtLogin;

  mainWindow = new BrowserWindow({
    width: 1300,
    height: 820,
    minWidth: 1000,
    minHeight: 620,
    frame: false,
    show: !startHidden,
    backgroundColor: '#0d1117',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile('index.html');

  // Hide to tray on close — quit only from tray menu
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on('closed', () => { mainWindow = null; });

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
  pushStatsData();
  setTimeout(pushProcessData, 500);
  statsInterval = setInterval(pushStatsData, 1500);
  processInterval = setInterval(pushProcessData, 4000);
}

// IPC handlers
ipcMain.handle('force-refresh', async () => {
  await pushProcessData();
  return true;
});

ipcMain.handle('is-admin', () => {
  return new Promise((resolve) => {
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

ipcMain.handle('get-startup-setting', () => app.getLoginItemSettings().openAtLogin);

ipcMain.handle('set-startup-setting', (_, enable) => {
  app.setLoginItemSettings({ openAtLogin: !!enable });
  return app.getLoginItemSettings().openAtLogin;
});

ipcMain.on('window-minimize', () => mainWindow?.minimize());
ipcMain.on('window-maximize', () => {
  if (mainWindow?.isMaximized()) mainWindow.unmaximize();
  else mainWindow?.maximize();
});
ipcMain.on('window-close', () => mainWindow?.close()); // triggers hide-to-tray

function ensureDefaultStartup() {
  const flagPath = path.join(app.getPath('userData'), '.startup-configured');
  if (!fs.existsSync(flagPath)) {
    app.setLoginItemSettings({ openAtLogin: true });
    fs.writeFileSync(flagPath, '1');
  }
}

app.whenReady().then(() => {
  ensureDefaultStartup();
  createWindow();
  createTray();
  startRefreshCycles();

  app.on('activate', () => {
    if (!mainWindow) createWindow();
  });
});

app.on('window-all-closed', () => {
  clearInterval(processInterval);
  clearInterval(statsInterval);
  if (!tray) app.quit(); // safety: no tray means quit normally
});
