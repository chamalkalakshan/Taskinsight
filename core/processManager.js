'use strict';

const si = require('systeminformation');
const { categorize } = require('./categorizer');
const { analyzeRisk } = require('./riskAnalyzer');
const { getStartupApps } = require('./startupManager');

// Built-in knowledge base — explains what common processes do
const PROCESS_KNOWLEDGE = {
  'svchost.exe': { desc: 'Service Host — runs Windows background services. Multiple instances are completely normal.', publisher: 'Microsoft' },
  'lsass.exe': { desc: 'Local Security Authority — manages user logins, password changes, and Windows security policies. Essential.', publisher: 'Microsoft' },
  'explorer.exe': { desc: 'Windows Explorer — your desktop, taskbar, and file manager. One instance is normal.', publisher: 'Microsoft' },
  'dwm.exe': { desc: 'Desktop Window Manager — renders visual effects like transparency and animations.', publisher: 'Microsoft' },
  'csrss.exe': { desc: 'Client/Server Runtime — core Windows process, manages console windows and shutdown.', publisher: 'Microsoft' },
  'wininit.exe': { desc: 'Windows Initialization — starts core Windows services at boot. Runs once.', publisher: 'Microsoft' },
  'winlogon.exe': { desc: 'Windows Logon — handles the login/logout screen and secure attention sequence (Ctrl+Alt+Del).', publisher: 'Microsoft' },
  'services.exe': { desc: 'Services Control Manager — starts, stops, and manages all Windows services.', publisher: 'Microsoft' },
  'runtimebroker.exe': { desc: 'Runtime Broker — manages permissions for Microsoft Store apps (camera, microphone, location).', publisher: 'Microsoft' },
  'searchindexer.exe': { desc: 'Windows Search Indexer — builds a search index of your files for fast search results.', publisher: 'Microsoft' },
  'msmpeng.exe': { desc: 'Windows Defender Antivirus — real-time malware protection. High CPU during scans is normal.', publisher: 'Microsoft' },
  'spoolsv.exe': { desc: 'Print Spooler — manages print jobs sent to your printer.', publisher: 'Microsoft' },
  'audiodg.exe': { desc: 'Windows Audio Device Graph — handles all audio processing and effects.', publisher: 'Microsoft' },
  'ctfmon.exe': { desc: 'CTF Loader — manages alternative text input methods and the language bar.', publisher: 'Microsoft' },
  'wmiprvse.exe': { desc: 'WMI Provider Host — allows programs to query Windows system information. Multiple instances are normal.', publisher: 'Microsoft' },
  'conhost.exe': { desc: 'Console Host — renders command-line windows (CMD, PowerShell). One per console window.', publisher: 'Microsoft' },
  'taskhostw.exe': { desc: 'Task Host for Windows — hosts scheduled tasks and Windows background services.', publisher: 'Microsoft' },
  'sihost.exe': { desc: 'Shell Infrastructure Host — powers the Start menu, Action Center, and taskbar.', publisher: 'Microsoft' },
  'fontdrvhost.exe': { desc: 'Font Driver Host — renders fonts for the Windows display system.', publisher: 'Microsoft' },
  'dllhost.exe': { desc: 'DLL Host — runs COM objects and legacy ActiveX components for Windows features.', publisher: 'Microsoft' },
  'searchapp.exe': { desc: 'Windows Search — the modern search UI that appears when you press the Windows key.', publisher: 'Microsoft' },
  'shellexperiencehost.exe': { desc: 'Shell Experience Host — renders immersive UI elements like the Start menu shell.', publisher: 'Microsoft' },
  'startmenuexperiencehost.exe': { desc: 'Start Menu Experience Host — the process behind the Windows 10/11 Start menu.', publisher: 'Microsoft' },
  'applicationframehost.exe': { desc: 'Application Frame Host — provides the window frame for Microsoft Store apps.', publisher: 'Microsoft' },
  'textinputhost.exe': { desc: 'Text Input Host — powers the touch keyboard and emoji panel.', publisher: 'Microsoft' },
  'securityhealthservice.exe': { desc: 'Windows Security Health Service — monitors and reports system security status.', publisher: 'Microsoft' },
  'chrome.exe': { desc: 'Google Chrome — web browser. Multiple processes are normal (one per tab/extension).', publisher: 'Google' },
  'msedge.exe': { desc: 'Microsoft Edge — web browser built on Chromium. Multiple processes are normal.', publisher: 'Microsoft' },
  'firefox.exe': { desc: 'Mozilla Firefox — open-source web browser.', publisher: 'Mozilla' },
  'brave.exe': { desc: 'Brave Browser — privacy-focused web browser.', publisher: 'Brave Software' },
  'opera.exe': { desc: 'Opera Browser — web browser with built-in VPN and ad blocker.', publisher: 'Opera Software' },
  'discord.exe': { desc: 'Discord — voice, video, and text chat for communities and gaming.', publisher: 'Discord Inc.' },
  'slack.exe': { desc: 'Slack — team communication and collaboration platform.', publisher: 'Slack Technologies' },
  'teams.exe': { desc: 'Microsoft Teams — chat, video calls, and file sharing for work.', publisher: 'Microsoft' },
  'zoom.exe': { desc: 'Zoom — video conferencing and online meetings.', publisher: 'Zoom Video Communications' },
  'steam.exe': { desc: 'Steam — digital gaming platform by Valve. Used to buy, download, and launch games.', publisher: 'Valve Corporation' },
  'onedrive.exe': { desc: 'Microsoft OneDrive — cloud storage that automatically syncs your files.', publisher: 'Microsoft' },
  'dropbox.exe': { desc: 'Dropbox — cloud file storage and synchronization service.', publisher: 'Dropbox, Inc.' },
  'code.exe': { desc: 'Visual Studio Code — lightweight but powerful source code editor.', publisher: 'Microsoft' },
  'devenv.exe': { desc: 'Visual Studio — full-featured IDE for professional software development.', publisher: 'Microsoft' },
  'node.exe': { desc: 'Node.js — JavaScript runtime for running scripts and server-side code.', publisher: 'OpenJS Foundation' },
  'python.exe': { desc: 'Python — general-purpose programming language interpreter.', publisher: 'Python Software Foundation' },
  'git.exe': { desc: 'Git — distributed version control system for tracking code changes.', publisher: 'Git Project' },
  'powershell.exe': { desc: 'Windows PowerShell — command-line shell and scripting language.', publisher: 'Microsoft' },
  'cmd.exe': { desc: 'Command Prompt — the classic Windows command-line interface.', publisher: 'Microsoft' },
  'taskmgr.exe': { desc: 'Task Manager — built-in Windows process and performance monitor.', publisher: 'Microsoft' },
  'msiexec.exe': { desc: 'Windows Installer — runs when installing, repairing, or uninstalling software.', publisher: 'Microsoft' },
  'notepad.exe': { desc: 'Notepad — the simple built-in text editor.', publisher: 'Microsoft' },
  'nissrv.exe': { desc: 'Windows Defender Network Inspection Service — inspects network traffic for threats.', publisher: 'Microsoft' },
};

let startupData = { apps: [], names: new Set(), paths: new Set() };
let serviceNames = new Set();
let lastStartupRefresh = 0;
let cachedTotalRamBytes = 0; // used to derive memMB when mem_rss is unavailable on Windows

async function refreshStartupAndServices() {
  const now = Date.now();
  if (now - lastStartupRefresh < 30000) return; // Refresh every 30s
  lastStartupRefresh = now;

  try {
    startupData = await getStartupApps();
  } catch { /* ignore */ }

  try {
    const services = await si.services('*');
    serviceNames = new Set(
      services
        .filter(s => s.running)
        .map(s => (s.name || '').toLowerCase() + '.exe')
    );
  } catch { /* ignore */ }
}

async function getProcesses() {
  await refreshStartupAndServices();

  // Fetch RAM total if not cached — used to derive memMB from percentage on Windows
  if (!cachedTotalRamBytes) {
    try {
      const mem = await si.mem();
      cachedTotalRamBytes = mem.total || 0;
    } catch { /* ignore */ }
  }

  let procs;
  try {
    const result = await si.processes();
    procs = result.list || [];
  } catch {
    return [];
  }

  return procs.map(p => {
    const nameLower = (p.name || '').toLowerCase();
    const risk = analyzeRisk({ name: p.name || '', path: p.path || '', cpu: p.cpu || 0 });
    const category = risk.level === 'high' || risk.level === 'critical'
      ? 'suspicious'
      : categorize(
          { name: p.name || '', path: p.path || '', user: p.user || '' },
          startupData.paths,
          startupData.names,
          serviceNames,
        );

    const knowledge = PROCESS_KNOWLEDGE[nameLower] || null;

    // mem_rss is often 0 on Windows — fall back to percentage-based estimate
    const memRssBytes = p.mem_rss || 0;
    const memMB = memRssBytes > 0
      ? Math.round(memRssBytes / (1024 * 1024) * 10) / 10
      : (cachedTotalRamBytes > 0 && p.mem > 0)
        ? Math.round((p.mem / 100) * cachedTotalRamBytes / (1024 * 1024) * 10) / 10
        : 0;

    // systeminformation returns "unknown" state for most Windows processes — normalise
    const rawState = (p.state || '').toLowerCase();
    const status = rawState === 'running' ? 'Running'
      : rawState === 'sleeping' || rawState === 'idle' ? 'Sleeping'
      : rawState === 'stopped' ? 'Stopped'
      : rawState === 'zombie' ? 'Zombie'
      : 'Running'; // default: if the process is in the list, it's running

    return {
      pid: p.pid,
      parentPid: p.parentPid,
      name: p.name || 'Unknown',
      cpu: Math.round((p.cpu || 0) * 10) / 10,
      memMB,
      memPercent: Math.round((p.mem || 0) * 10) / 10,
      status,
      path: p.path || '',
      user: p.user || '',
      started: p.started || '',
      command: p.command || '',
      threads: p.threads || 0,
      category,
      risk: risk.level,
      riskScore: risk.score,
      riskReasons: risk.reasons,
      description: knowledge ? knowledge.desc : '',
      publisher: knowledge ? knowledge.publisher : '',
    };
  });
}

async function getSystemStats() {
  try {
    const [load, mem, disk, net] = await Promise.all([
      si.currentLoad(),
      si.mem(),
      si.fsSize(),
      si.networkStats(),
    ]);

    const diskC = (disk || []).find(d => d.mount === 'C:' || d.mount === '/') || disk[0] || {};
    const netPrimary = (net || [])[0] || {};

    return {
      cpu: Math.round(load.currentLoad || 0),
      memPercent: Math.round(((mem.used || 0) / (mem.total || 1)) * 100),
      memUsedGB: ((mem.used || 0) / 1073741824).toFixed(1),
      memTotalGB: ((mem.total || 0) / 1073741824).toFixed(1),
      diskPercent: diskC.size ? Math.round((diskC.used / diskC.size) * 100) : 0,
      diskUsedGB: ((diskC.used || 0) / 1073741824).toFixed(0),
      diskTotalGB: ((diskC.size || 0) / 1073741824).toFixed(0),
      netRxMB: ((netPrimary.rx_sec || 0) / (1024 * 1024)).toFixed(2),
      netTxMB: ((netPrimary.tx_sec || 0) / (1024 * 1024)).toFixed(2),
    };
  } catch {
    return { cpu: 0, memPercent: 0, memUsedGB: '0', memTotalGB: '0', diskPercent: 0 };
  }
}

module.exports = { getProcesses, getSystemStats };
