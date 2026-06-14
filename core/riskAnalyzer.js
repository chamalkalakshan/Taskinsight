'use strict';

const KNOWN_SAFE = new Set([
  'system', 'system idle process', 'smss.exe', 'csrss.exe', 'wininit.exe',
  'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'dwm.exe',
  'explorer.exe', 'taskhostw.exe', 'conhost.exe', 'fontdrvhost.exe',
  'sihost.exe', 'runtimebroker.exe', 'searchindexer.exe', 'spoolsv.exe',
  'msmpeng.exe', 'nissrv.exe', 'audiodg.exe', 'ctfmon.exe', 'dllhost.exe',
  'wuauclt.exe', 'wmiprvse.exe', 'registry', 'secure system',
  'memory compression', 'msdtc.exe', 'taskhost.exe', 'lsm.exe',
  'chrome.exe', 'msedge.exe', 'firefox.exe', 'opera.exe', 'brave.exe',
  'discord.exe', 'slack.exe', 'teams.exe', 'zoom.exe', 'steam.exe',
  'onedrive.exe', 'dropbox.exe', 'code.exe', 'devenv.exe', 'node.exe',
  'python.exe', 'git.exe', 'powershell.exe', 'cmd.exe', 'notepad.exe',
  'msiexec.exe', 'searchapp.exe', 'startmenuexperiencehost.exe',
  'textinputhost.exe', 'applicationframehost.exe', 'shellexperiencehost.exe',
  'securityhealthservice.exe', 'securityhealthsystray.exe',
  'unsecapp.exe', 'wermgr.exe', 'wlanext.exe', 'taskmgr.exe',
]);

const SYSTEM32_PATHS = [
  'c:\\windows\\system32',
  'c:\\windows\\syswow64',
  'c:\\windows\\winsxs',
];

const PROGRAM_FILES_PATHS = [
  'c:\\program files\\',
  'c:\\program files (x86)\\',
];

const SUSPICIOUS_PATHS = [
  '\\temp\\', '\\tmp\\', 'appdata\\local\\temp',
  'c:\\windows\\temp\\', '\\downloads\\', '\\desktop\\',
  'appdata\\roaming\\', '\\public\\',
];

const VERY_SUSPICIOUS_PATHS = [
  '\\temp\\', '\\tmp\\', 'appdata\\local\\temp', 'c:\\windows\\temp',
  'c:\\users\\public',
];

const KNOWN_SYSTEM_NAMES = new Set([
  'svchost', 'lsass', 'csrss', 'smss', 'wininit', 'winlogon',
  'services', 'lsm', 'spoolsv', 'msdtc',
]);

const SUSPICIOUS_KEYWORDS = [
  'miner', 'keylog', 'inject', 'rootkit', 'backdoor', 'trojan',
  'stealer', 'cryptominer', 'ransomware', 'spyware', 'adware',
];

function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str.toLowerCase()) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function hasHighEntropy(name) {
  const baseName = name.replace(/\.[^.]+$/, '');
  if (baseName.length < 6) return false;
  const entropy = calculateEntropy(baseName);
  // > 3.5 suggests random/generated names (svchost=2.5, chrome=2.58, xuywqabc=3.0)
  return entropy > 3.5;
}

function isMasquerading(proc) {
  const nameLower = proc.name.toLowerCase();
  const pathLower = (proc.path || '').toLowerCase();
  if (!pathLower) return false;
  const baseName = nameLower.replace(/\.[^.]+$/, '');
  if (KNOWN_SYSTEM_NAMES.has(baseName)) {
    return !SYSTEM32_PATHS.some(sp => pathLower.startsWith(sp));
  }
  return false;
}

function analyzeRisk(proc) {
  const reasons = [];
  let score = 0;
  const nameLower = proc.name.toLowerCase();
  const pathLower = (proc.path || '').toLowerCase();

  // Quick exit for well-known safe processes in correct locations
  if (KNOWN_SAFE.has(nameLower)) {
    if (!pathLower || SYSTEM32_PATHS.some(sp => pathLower.startsWith(sp)) ||
        PROGRAM_FILES_PATHS.some(pp => pathLower.startsWith(pp))) {
      score = Math.max(0, score - 30);
      return { level: 'safe', score: 0, reasons: [] };
    }
  }

  // Masquerading check (system name, wrong location)
  if (isMasquerading(proc)) {
    score += 60;
    reasons.push('System process name running from unexpected location');
  }

  // Path-based scoring
  if (pathLower) {
    const inVeryBad = VERY_SUSPICIOUS_PATHS.some(sp => pathLower.includes(sp));
    const inBad = SUSPICIOUS_PATHS.some(sp => pathLower.includes(sp));

    if (inVeryBad) {
      score += 45;
      reasons.push('Running from a temporary or high-risk directory');
    } else if (inBad) {
      score += 20;
      reasons.push('Running from an unusual location (Downloads, Desktop, or AppData\\Roaming)');
    }

    if (SYSTEM32_PATHS.some(sp => pathLower.startsWith(sp))) score -= 25;
    else if (PROGRAM_FILES_PATHS.some(pp => pathLower.startsWith(pp))) score -= 10;
  } else {
    // No path — either kernel process or hidden
    if (nameLower !== 'system' && nameLower !== 'system idle process' &&
        nameLower !== 'registry' && nameLower !== 'secure system' &&
        nameLower !== 'memory compression') {
      score += 15;
      reasons.push('No executable path found');
    }
  }

  // High entropy name (random-looking)
  if (hasHighEntropy(proc.name)) {
    score += 25;
    reasons.push('Process name appears randomly generated');
  }

  // Suspicious keywords in name
  const suspKeyword = SUSPICIOUS_KEYWORDS.find(kw => nameLower.includes(kw));
  if (suspKeyword) {
    score += 35;
    reasons.push(`Name contains suspicious keyword: "${suspKeyword}"`);
  }

  // Resource abuse flags
  if (proc.cpu > 80) {
    score += 8;
    reasons.push('Extremely high CPU usage');
  }

  score = Math.max(0, Math.min(100, score));

  let level;
  if (score <= 10) level = 'safe';
  else if (score <= 30) level = 'low';
  else if (score <= 55) level = 'medium';
  else if (score <= 75) level = 'high';
  else level = 'critical';

  return { level, score, reasons };
}

module.exports = { analyzeRisk };
