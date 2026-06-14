# TaskInsight

A Windows desktop app that shows you exactly what is running on your machine, grouped into categories that make sense, with plain-English explanations and risk scoring.

![TaskInsight](assets/icon.png)

---

## What it does

Most task managers throw a raw list of process names at you. TaskInsight groups them, explains them, and flags anything suspicious.

- Groups every running process into categories: System, Services, Security, Browsers, Startup Apps, Installed Apps, User Apps, Background, and Suspicious
- Shows live CPU, RAM, and disk usage
- Explains what each known process does in plain English
- Scores every process for risk (Safe / Low / Medium / High / Critical)
- Detects masquerading processes (e.g. a fake `svchost.exe` running from an unusual path)
- Reads the Windows registry to identify startup entries
- Lets you kill, suspend, or resume any process
- Runs silently in the system tray at startup

---

## Screenshots

> Launch the app and check the Startup Apps or Suspicious categories first.

---

## Installation

### Option 1: Run from source

Requirements: [Node.js](https://nodejs.org) (v18 or later)

```bash
git clone https://github.com/chamalkalakshan/Taskinsight.git
cd Taskinsight
npm install
npm start
```

### Option 2: Portable build (no Node.js required)

1. Download the latest ZIP from [Releases](https://github.com/chamalkalakshan/Taskinsight/releases)
2. Extract it anywhere
3. Run `install.bat` to copy the app to `%LocalAppData%\TaskInsight` and create a desktop shortcut
4. Or just double-click `TaskInsight.exe` directly

> Windows SmartScreen may warn about the app because it is not code-signed. Click **More info** then **Run anyway**.

---

## Build a distributable

```bash
npm run dist
```

This uses `@electron/packager` and outputs a self-contained folder under `dist/`. No Node.js needed on the target machine.

---

## Running as Administrator

Some processes are only visible to admin accounts. If the app starts in **Limited Mode**, click the badge in the bottom-left of the sidebar. A UAC prompt will appear and the app will relaunch with full privileges.

---

## System Tray

TaskInsight lives in the system tray. Closing the window hides it rather than quitting it. To fully exit, right-click the tray icon and choose **Quit TaskInsight**.

By default the app registers itself to run at Windows login. You can toggle this off from the sidebar.

---

## Risk Scoring

Each process is scored on several signals:

| Signal | What it checks |
|---|---|
| Masquerade detection | Known system process names running from unexpected paths |
| Entropy analysis | Randomly generated names (high character entropy) |
| Path scoring | Processes in temp folders, AppData, or with no path at all |
| Keyword matching | Names that match known suspicious patterns |
| CPU spike | Unusually high CPU from an otherwise idle-looking process |

Scores map to levels: **Safe** (0-10), **Low** (11-30), **Medium** (31-55), **High** (56-75), **Critical** (76+).

---

## Process Actions

Select any process in the table to open the details panel, then:

| Action | What it does |
|---|---|
| Kill | Force-terminates the process (`taskkill /F`) |
| Suspend / Resume | Pauses and unpauses the process (requires [Sysinternals PsSuspend](https://learn.microsoft.com/en-us/sysinternals/downloads/pssuspend)) |
| Open Location | Opens the folder containing the executable in Explorer |
| Search Online | Google search for the process name |

---

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `Ctrl+F` | Focus the search box |
| `Ctrl+R` | Force refresh process list |
| `Escape` | Clear search or close details panel |
| `Delete` | Kill the selected process |

---

## Tech Stack

- [Electron](https://www.electronjs.org/) 28
- [systeminformation](https://systeminformation.io/) for process and hardware data
- [winreg](https://www.npmjs.com/package/winreg) for reading Windows startup registry keys
- Vanilla JS renderer with no frontend framework

---

## Project Structure

```
taskmanager/
  main.js              # Electron main process, IPC handlers
  preload.js           # Context bridge (renderer <-> main)
  renderer.js          # UI logic
  renderer.css         # Styles
  index.html           # App shell
  core/
    processManager.js  # Fetches and maps process data
    categorizer.js     # Assigns categories to processes
    riskAnalyzer.js    # Scores each process for risk
    startupManager.js  # Reads startup entries from registry
  assets/
    icon.png           # App icon
    icon.ico           # Packaged exe icon
    tray.png           # System tray icon (32x32)
```

---

## License

MIT
