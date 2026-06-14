'use strict';

const SYSTEM_PROCESS_NAMES = new Set([
  'system', 'system idle process', 'smss.exe', 'csrss.exe', 'wininit.exe',
  'winlogon.exe', 'services.exe', 'lsass.exe', 'lsm.exe', 'dwm.exe',
  'fontdrvhost.exe', 'sihost.exe', 'taskhostw.exe', 'conhost.exe',
  'searchindexer.exe', 'msdtc.exe', 'wuauclt.exe', 'wmiprvse.exe',
  'audiodg.exe', 'dllhost.exe', 'registry', 'secure system',
  'memory compression', 'wermgr.exe', 'unsecapp.exe',
  'runtimebroker.exe', 'shellexperiencehost.exe', 'startmenuexperiencehost.exe',
  'applicationframehost.exe', 'textinputhost.exe', 'searchapp.exe',
  'securityhealthservice.exe', 'securityhealthsystray.exe',
  'ctfmon.exe', 'wlanext.exe', 'spoolsv.exe',
]);

const SECURITY_PROCESS_NAMES = new Set([
  'msmpeng.exe', 'nissrv.exe', 'msseces.exe', 'mbam.exe', 'mbamservice.exe',
  'avgui.exe', 'avguard.exe', 'avp.exe', 'ekrn.exe', 'bdservicehost.exe',
  'bullguard.exe', 'ccuac.exe', 'mcshield.exe', 'mfemms.exe', 'mfevtps.exe',
  'avgnt.exe', 'avastsvc.exe', 'avastui.exe', 'mbamtray.exe',
]);

const BROWSER_PROCESS_NAMES = new Set([
  'chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe', 'brave.exe',
  'iexplore.exe', 'vivaldi.exe', 'chromium.exe', 'waterfox.exe',
  'palemoon.exe', 'operagx.exe', 'thorium.exe', 'librewolf.exe',
  'browser.exe', 'seamonkey.exe',
]);

const SYSTEM_PATHS = [
  'c:\\windows\\system32',
  'c:\\windows\\syswow64',
  'c:\\windows\\',
  'c:\\program files\\windows defender',
];

const PROGRAM_FILES_PATHS = [
  'c:\\program files\\',
  'c:\\program files (x86)\\',
];

function categorize(proc, startupPaths, startupNames, serviceNames) {
  const nameLower = proc.name.toLowerCase();
  const pathLower = (proc.path || '').toLowerCase();

  // System kernel processes (no path, or from system locations)
  if (SYSTEM_PROCESS_NAMES.has(nameLower)) {
    return 'system';
  }

  // Svchost.exe — show as services
  if (nameLower === 'svchost.exe') {
    return 'services';
  }

  // Security software
  if (SECURITY_PROCESS_NAMES.has(nameLower)) {
    return 'security';
  }

  // Browsers
  if (BROWSER_PROCESS_NAMES.has(nameLower)) {
    return 'browser';
  }

  // Windows services (matched by service name list)
  if (serviceNames && serviceNames.has(nameLower)) {
    return 'services';
  }

  // Startup apps (matched by exe name or path)
  if (startupNames && startupNames.has(nameLower)) {
    return 'startup';
  }
  if (startupPaths && pathLower && startupPaths.has(pathLower)) {
    return 'startup';
  }

  // Installed apps
  if (pathLower && PROGRAM_FILES_PATHS.some(pp => pathLower.startsWith(pp))) {
    return 'apps';
  }

  // Windows path but not a known system process — treat as background system task
  if (pathLower && SYSTEM_PATHS.some(sp => pathLower.startsWith(sp))) {
    return 'system';
  }

  // User-space processes (running as a real user, from their profile)
  if (proc.user && proc.user !== 'SYSTEM' && proc.user !== 'LOCAL SERVICE' &&
      proc.user !== 'NETWORK SERVICE' && proc.user !== '' &&
      pathLower && pathLower.includes('c:\\users\\')) {
    return 'user';
  }

  // Anything left with a user context = background user task
  if (proc.user && proc.user !== 'SYSTEM' && proc.user !== 'LOCAL SERVICE' &&
      proc.user !== 'NETWORK SERVICE') {
    return 'background';
  }

  return 'background';
}

module.exports = { categorize };
