'use strict';

const path = require('path');

const STARTUP_KEYS = [
  { hive: 'HKCU', key: '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' },
  { hive: 'HKLM', key: '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' },
  { hive: 'HKCU', key: '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce' },
  { hive: 'HKLM', key: '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce' },
  { hive: 'HKLM', key: '\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run' },
];

// Extracts exe path from a command string like: "C:\Prog\foo.exe" --arg /flag
function extractExePath(cmd) {
  if (!cmd) return '';
  const cleaned = cmd.trim();
  const quoted = cleaned.match(/^"([^"]+)"/);
  if (quoted) return quoted[1];
  const space = cleaned.indexOf(' ');
  return space > -1 ? cleaned.slice(0, space) : cleaned;
}

async function getStartupApps() {
  let Registry;
  try {
    Registry = require('winreg');
  } catch {
    return { apps: [], names: new Set(), paths: new Set() };
  }

  const apps = [];
  const names = new Set();
  const paths = new Set();

  for (const { hive, key } of STARTUP_KEYS) {
    try {
      const reg = new Registry({ hive: Registry[hive], key });
      const items = await new Promise((resolve) => {
        reg.values((err, vals) => resolve(err ? [] : vals));
      });

      for (const item of items) {
        const exePath = extractExePath(item.value).toLowerCase();
        const exeName = path.basename(exePath).toLowerCase();

        apps.push({
          name: item.name,
          command: item.value,
          exePath,
          exeName,
          hive,
          key,
        });

        if (exeName) names.add(exeName);
        if (exePath) paths.add(exePath);
      }
    } catch {
      // Registry key may not exist or may be inaccessible
    }
  }

  return { apps, names, paths };
}

module.exports = { getStartupApps };
