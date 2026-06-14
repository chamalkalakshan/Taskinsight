'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  // Data streams
  onProcessUpdate: (cb) => ipcRenderer.on('process-update', (_, d) => cb(d)),
  onStatsUpdate: (cb) => ipcRenderer.on('stats-update', (_, d) => cb(d)),

  // One-shot queries
  forceRefresh: () => ipcRenderer.invoke('force-refresh'),
  isAdmin: () => ipcRenderer.invoke('is-admin'),

  // Process actions
  killProcess: (pid) => ipcRenderer.invoke('kill-process', pid),
  suspendProcess: (pid) => ipcRenderer.invoke('suspend-process', pid),
  resumeProcess: (pid) => ipcRenderer.invoke('resume-process', pid),
  openFileLocation: (filePath) => ipcRenderer.invoke('open-file-location', filePath),
  searchOnline: (query) => ipcRenderer.invoke('search-online', query),

  // Window controls
  minimize: () => ipcRenderer.send('window-minimize'),
  maximize: () => ipcRenderer.send('window-maximize'),
  close: () => ipcRenderer.send('window-close'),
});
