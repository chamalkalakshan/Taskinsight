'use strict';

/* ====== State ====== */
const state = {
  processes: [],
  filtered: [],
  selected: null,
  category: 'all',
  search: '',
  sortCol: 'cpu',
  sortDir: 'desc',
  autoRefresh: true,
  detailsOpen: false,
  lastRefresh: null,
  isAdmin: false,
  suspendedPids: new Set(), // tracks which PIDs are currently suspended
};

const CATEGORY_COLORS = {
  system:     '#58a6ff',
  services:   '#bc8cff',
  security:   '#3fb950',
  apps:       '#4ac26b',
  browser:    '#ffa657',
  startup:    '#e3b341',
  user:       '#79c0ff',
  background: '#6e7681',
  suspicious: '#f85149',
};

const RISK_ORDER = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };

/* ====== DOM Refs ====== */
const $ = id => document.getElementById(id);

// Stats
const cpuBar   = $('cpuBar');   const cpuVal   = $('cpuVal');
const ramBar   = $('ramBar');   const ramVal   = $('ramVal');   const ramSub   = $('ramSub');
const diskBar  = $('diskBar');  const diskVal  = $('diskVal');  const diskSub  = $('diskSub');
const procCountLabel = $('processCountLabel');
const suspPill       = $('suspiciousPill');
const suspCountLabel = $('suspiciousCountLabel');

// Category counts
const counts = {};
['all','system','services','security','apps','browser','startup','user','background','suspicious']
  .forEach(c => { counts[c] = $(`count-${c}`); });

// Table
const tableBody = $('tableBody');
const searchInput = $('searchInput');
const clearSearchBtn = $('btnClearSearch');
const sortSelect = $('sortSelect');

// Details
const detailsPanel  = $('detailsPanel');
const handleLabel   = $('handleLabel');
const btnToggle     = $('btnToggleDetails');
const dName         = $('dName');
const dRiskBadge    = $('dRiskBadge');
const dDesc         = $('dDesc');
const dPid          = $('dPid');
const dStatus       = $('dStatus');
const dUser         = $('dUser');
const dPublisher    = $('dPublisher');
const dThreads      = $('dThreads');
const dStarted      = $('dStarted');
const dPath         = $('dPath');
const dCommand      = $('dCommand');
const riskSection   = $('riskSection');
const riskReasonsList = $('riskReasonsList');

// Actions
const btnKill        = $('btnKill');
const btnSuspend     = $('btnSuspend');
const btnLocation    = $('btnLocation');
const btnSearchOnline = $('btnSearchOnline');

// Status bar
const statusTotal    = $('statusTotal');
const statusFiltered = $('statusFiltered');
const statusAdmin    = $('statusAdmin');
const statusRefreshLabel = $('statusRefreshLabel');
const statusLastRefresh  = $('statusLastRefresh');
const adminBadge     = $('adminBadge');
const adminLabel     = $('adminLabel');

const toast = $('toast');

/* ====== Toast ====== */
let toastTimer = null;
function showToast(msg, type = 'info', duration = 2500) {
  clearTimeout(toastTimer);
  toast.textContent = msg;
  toast.className = `toast toast-${type}`;
  toastTimer = setTimeout(() => { toast.className = 'toast hidden'; }, duration);
}

/* ====== Stats Update ====== */
window.api.onStatsUpdate((stats) => {
  const cpuPct = stats.cpu || 0;
  cpuBar.style.width = cpuPct + '%';
  cpuVal.textContent = cpuPct + '%';
  cpuBar.className = 'stat-bar-fill cpu-fill' + (cpuPct > 85 ? ' stat-fill-danger' : cpuPct > 65 ? ' stat-fill-warn' : '');

  const ramPct = stats.memPercent || 0;
  ramBar.style.width = ramPct + '%';
  ramVal.textContent = ramPct + '%';
  ramBar.className = 'stat-bar-fill ram-fill' + (ramPct > 85 ? ' stat-fill-danger' : ramPct > 70 ? ' stat-fill-warn' : '');
  ramSub.textContent = `${stats.memUsedGB} / ${stats.memTotalGB} GB`;

  const diskPct = stats.diskPercent || 0;
  diskBar.style.width = diskPct + '%';
  diskVal.textContent = diskPct + '%';
  diskBar.className = 'stat-bar-fill disk-fill' + (diskPct > 90 ? ' stat-fill-danger' : diskPct > 75 ? ' stat-fill-warn' : '');
  diskSub.textContent = `${stats.diskUsedGB || '?'} / ${stats.diskTotalGB || '?'} GB`;
});

/* ====== Process Update ====== */
window.api.onProcessUpdate((processes) => {
  if (!state.autoRefresh) return;
  state.processes = processes || [];
  // M-3: remove stale suspended PIDs for reused process slots
  const livePids = new Set(state.processes.map(p => p.pid));
  for (const pid of state.suspendedPids) {
    if (!livePids.has(pid)) state.suspendedPids.delete(pid);
  }
  state.lastRefresh = new Date();
  applyFilterAndRender();
  updateCategoryCounts();
  updateStatusBar();
});

/* ====== Filter + Sort ====== */
function applyFilterAndRender() {
  let list = state.processes;

  // Category filter
  if (state.category !== 'all') {
    list = list.filter(p => p.category === state.category);
  }

  // Search filter
  const q = state.search.toLowerCase().trim();
  if (q) {
    list = list.filter(p =>
      p.name.toLowerCase().includes(q) ||
      (p.path || '').toLowerCase().includes(q) ||
      (p.user || '').toLowerCase().includes(q) ||
      String(p.pid).includes(q)
    );
  }

  // Sort
  list = [...list].sort((a, b) => {
    let diff = 0;
    switch (state.sortCol) {
      case 'name':   diff = a.name.localeCompare(b.name); break;
      case 'pid':    diff = a.pid - b.pid; break;
      case 'cpu':    diff = a.cpu - b.cpu; break;
      case 'memory': diff = a.memMB - b.memMB; break;
      case 'risk':   diff = (RISK_ORDER[a.risk] || 0) - (RISK_ORDER[b.risk] || 0); break;
    }
    return state.sortDir === 'desc' ? -diff : diff;
  });

  state.filtered = list;
  renderTable(list);
}

/* ====== Render Table ====== */
function renderTable(list) {
  if (list.length === 0) {
    tableBody.innerHTML = '<tr class="empty-row"><td colspan="7">No processes found</td></tr>';
    return;
  }

  // Use a document fragment for performance
  const frag = document.createDocumentFragment();

  for (const proc of list) {
    const tr = document.createElement('tr');
    tr.dataset.pid = proc.pid;

    if (proc.risk === 'high' || proc.risk === 'critical') {
      tr.classList.add('row-suspicious');
    }
    if (state.selected && state.selected.pid === proc.pid) {
      tr.classList.add('selected');
    }

    const cpuWidth = Math.min(proc.cpu, 100);
    const cpuClass = proc.cpu > 80 ? 'danger' : proc.cpu > 40 ? 'warn' : '';
    const catColor = CATEGORY_COLORS[proc.category] || '#6e7681';
    const memText = proc.memMB >= 1000
      ? `${(proc.memMB / 1024).toFixed(1)} GB`
      : `${proc.memMB.toFixed(0)} MB`;

    tr.innerHTML = `
      <td class="cat-${proc.category}">
        <div class="name-cell">
          <div class="cat-indicator" style="background:${catColor}"></div>
          <span class="proc-name" title="${escHtml(proc.name)}">${escHtml(proc.name)}</span>
        </div>
      </td>
      <td style="color:var(--text2)">${proc.pid}</td>
      <td><span class="status-badge ${getStatusClass(proc.status)}">${escHtml(proc.status || '?')}</span></td>
      <td>
        <div class="cpu-cell">
          <div class="cpu-mini-bar"><div class="cpu-mini-fill ${cpuClass}" style="width:${cpuWidth}%"></div></div>
          <span>${proc.cpu.toFixed(1)}%</span>
        </div>
      </td>
      <td>${memText}</td>
      <td><span class="risk-badge risk-${proc.risk}">${proc.risk.toUpperCase()}</span></td>
      <td style="color:var(--text2);font-size:11.5px" title="${escHtml(proc.user)}">${escHtml(truncate(proc.user, 20))}</td>
    `;

    tr.addEventListener('click', () => selectProcess(proc, tr));
    frag.appendChild(tr);
  }

  tableBody.innerHTML = '';
  tableBody.appendChild(frag);
}

/* ====== Category Counts ====== */
function updateCategoryCounts() {
  const all = state.processes;
  const c = { all: all.length };
  for (const cat of Object.keys(counts)) {
    if (cat !== 'all') c[cat] = all.filter(p => p.category === cat).length;
  }

  for (const [cat, el] of Object.entries(counts)) {
    if (el) el.textContent = c[cat] || 0;
  }

  // Stats bar pill always shows total (not filtered)
  procCountLabel.textContent = `${all.length} process${all.length !== 1 ? 'es' : ''}`;

  const suspCount = c.suspicious || 0;
  if (suspCount > 0) {
    suspPill.style.display = 'flex';
    suspCountLabel.textContent = `${suspCount} suspicious`;
    const suspBtn = document.querySelector('[data-cat="suspicious"]');
    if (suspBtn) suspBtn.classList.add('has-items');
  } else {
    suspPill.style.display = 'none';
  }
}

/* ====== Select Process ====== */
function selectProcess(proc, tr) {
  // Deselect previous
  document.querySelectorAll('#tableBody tr.selected').forEach(r => r.classList.remove('selected'));
  tr.classList.add('selected');

  state.selected = proc;
  populateDetails(proc);

  if (!state.detailsOpen) toggleDetails(true);
}

/* ====== Details Panel ====== */
function populateDetails(proc) {
  handleLabel.textContent = proc.name;
  dName.textContent = proc.name;

  // Risk badge
  dRiskBadge.innerHTML = `<span class="risk-badge risk-${proc.risk}">${proc.risk.toUpperCase()}</span>`;

  // Process description
  if (proc.description) {
    dDesc.textContent = `ℹ ${proc.description}`;
    dDesc.style.display = 'block';
  } else {
    dDesc.style.display = 'none';
  }

  dPid.textContent        = proc.pid;
  dStatus.textContent     = proc.status || '—';
  dUser.textContent       = proc.user || '—';
  dPublisher.textContent  = proc.publisher || '—';
  dThreads.textContent    = proc.threads || '—';
  dStarted.textContent    = proc.started ? formatTime(proc.started) : '—';
  dPath.textContent       = proc.path || 'No path available';
  dCommand.textContent    = proc.command || '—';

  // Risk reasons
  if (proc.riskReasons && proc.riskReasons.length > 0) {
    riskSection.style.display = 'block';
    riskReasonsList.innerHTML = proc.riskReasons
      .map(r => `<li class="risk-reason-item">⚠ ${escHtml(r)}</li>`)
      .join('');
  } else {
    riskSection.style.display = 'none';
  }

  // Enable/disable action buttons based on available info
  btnLocation.disabled = !proc.path;
  btnSuspend.disabled  = false;
  btnKill.disabled     = false;
  updateSuspendButton(proc.pid);
}

function toggleDetails(forceOpen) {
  state.detailsOpen = forceOpen !== undefined ? forceOpen : !state.detailsOpen;
  if (state.detailsOpen) {
    detailsPanel.classList.remove('panel-collapsed');
    detailsPanel.classList.add('panel-expanded');
  } else {
    detailsPanel.classList.add('panel-collapsed');
    detailsPanel.classList.remove('panel-expanded');
  }
}

/* ====== Status Bar ====== */
function updateStatusBar() {
  const total = state.processes.length;
  const shown = state.filtered.length;
  statusTotal.textContent = `${total} total processes`;
  statusFiltered.textContent = shown !== total ? `${shown} shown` : '';

  if (state.lastRefresh) {
    const secs = Math.round((Date.now() - state.lastRefresh) / 1000);
    statusLastRefresh.textContent = secs < 5 ? 'Just refreshed' : `Refreshed ${secs}s ago`;
  }
}

// Tick status bar every second
setInterval(updateStatusBar, 1000);

/* ====== Admin Check ====== */
window.api.isAdmin().then(isAdmin => {
  state.isAdmin = isAdmin;
  if (isAdmin) {
    adminLabel.textContent = 'Running as Admin';
    adminLabel.className = 'admin-ok';
    adminBadge.title = 'Running with administrator privileges — all processes visible';
    adminBadge.style.cursor = 'default';
    statusAdmin.textContent = 'Admin ✓';
    statusAdmin.className = 'status-tag tag-on';
  } else {
    adminLabel.textContent = 'Limited Mode — click to elevate';
    adminLabel.className = 'admin-no';
    adminBadge.title = 'Click to relaunch as Administrator';
    adminBadge.style.cursor = 'pointer';
    statusAdmin.textContent = 'Not Admin';
    statusAdmin.className = 'status-tag tag-warn';

    adminBadge.addEventListener('click', async () => {
      if (!confirm('Relaunch TaskInsight as Administrator?\n\nWindows will show a UAC prompt.')) return;
      await window.api.relaunchAsAdmin();
    }, { once: true });
  }
}).catch(() => {});

/* ====== Event: Category Buttons ====== */
document.querySelectorAll('.cat-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.cat-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.category = btn.dataset.cat;
    applyFilterAndRender();
  });
});

/* ====== Event: Search ====== */
searchInput.addEventListener('input', () => {
  state.search = searchInput.value;
  clearSearchBtn.style.display = state.search ? 'block' : 'none';
  applyFilterAndRender();
});
clearSearchBtn.addEventListener('click', () => {
  searchInput.value = '';
  state.search = '';
  clearSearchBtn.style.display = 'none';
  applyFilterAndRender();
  searchInput.focus();
});

/* ====== Event: Sort Select ====== */
sortSelect.addEventListener('change', () => {
  state.sortCol = sortSelect.value;
  applyFilterAndRender();
});

/* ====== Event: Table Header Sort ====== */
document.querySelectorAll('.th-sortable').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.col;
    if (state.sortCol === col) {
      state.sortDir = state.sortDir === 'desc' ? 'asc' : 'desc';
    } else {
      state.sortCol = col;
      state.sortDir = 'desc';
      // Sync select dropdown
      if (sortSelect.querySelector(`option[value="${col}"]`)) {
        sortSelect.value = col;
      }
    }
    document.querySelectorAll('.th-sortable').forEach(t => t.classList.remove('sorted'));
    th.classList.add('sorted');
    applyFilterAndRender();
  });
});

/* ====== Event: Refresh ====== */
$('btnRefresh').addEventListener('click', async () => {
  showToast('Refreshing processes...', 'info', 1500);
  await window.api.forceRefresh();
});

/* ====== Event: Auto-refresh Toggle ====== */
$('btnAutoRefresh').addEventListener('click', () => {
  state.autoRefresh = !state.autoRefresh;
  const btn = $('btnAutoRefresh');
  if (state.autoRefresh) {
    btn.classList.add('active');
    statusRefreshLabel.textContent = 'Auto ✓';
    statusRefreshLabel.className = 'status-tag tag-on';
    showToast('Auto-refresh enabled', 'success');
  } else {
    btn.classList.remove('active');
    statusRefreshLabel.textContent = 'Manual';
    statusRefreshLabel.className = 'status-tag tag-off';
    showToast('Auto-refresh paused', 'info');
  }
});

/* ====== Event: Details Toggle ====== */
btnToggle.addEventListener('click', () => {
  if (!state.detailsOpen && !state.selected) return;
  toggleDetails();
});

/* ====== Event: Kill Process ====== */
btnKill.addEventListener('click', async () => {
  if (!state.selected) return;
  const { name, pid } = state.selected;
  if (pid <= 4) {
    showToast('Cannot kill protected system process.', 'error', 3000);
    return;
  }
  if (!confirm(`Kill "${name}" (PID ${pid})?\n\nUnsaved work in this process will be lost.`)) return;
  const result = await window.api.killProcess(pid);
  if (result.success) {
    showToast(`Killed "${name}"`, 'success');
    state.selected = null;
    toggleDetails(false);
    handleLabel.textContent = 'Process Details';
  } else {
    showToast(`Failed to kill: ${result.error}`, 'error', 4000);
  }
});

/* ====== Event: Suspend / Resume Process ====== */
btnSuspend.addEventListener('click', async () => {
  if (!state.selected) return;
  const { pid, name } = state.selected;
  const isSuspended = state.suspendedPids.has(pid);

  if (isSuspended) {
    const result = await window.api.resumeProcess(pid);
    if (result.success) {
      state.suspendedPids.delete(pid);
      updateSuspendButton(pid);
      showToast(`Resumed "${name}"`, 'success');
    } else {
      showToast(result.error || 'Resume failed', 'error', 4000);
    }
  } else {
    const result = await window.api.suspendProcess(pid);
    if (result.success) {
      state.suspendedPids.add(pid);
      updateSuspendButton(pid);
      showToast(`Suspended "${name}"`, 'success');
    } else {
      showToast(result.error || 'Suspend failed', 'error', 4000);
    }
  }
});

function updateSuspendButton(pid) {
  const isSuspended = state.suspendedPids.has(pid);
  btnSuspend.innerHTML = isSuspended
    ? `<svg viewBox="0 0 16 16" fill="none"><path d="M3 8l5-4v8L3 8z" fill="currentColor"/><path d="M13 4v8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg> Resume`
    : `<svg viewBox="0 0 16 16" fill="none"><path d="M6 4v8M10 4v8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg> Suspend`;
  btnSuspend.style.color = isSuspended ? 'var(--risk-safe)' : '';
}

/* ====== Event: Open File Location ====== */
btnLocation.addEventListener('click', async () => {
  if (!state.selected || !state.selected.path) return;
  const result = await window.api.openFileLocation(state.selected.path);
  if (!result.success) showToast(result.error, 'error');
});

/* ====== Event: Search Online ====== */
btnSearchOnline.addEventListener('click', async () => {
  if (!state.selected) return;
  await window.api.searchOnline(state.selected.name);
});

/* ====== Event: Window Controls ====== */
$('btnMinimize').addEventListener('click', () => window.api.minimize());
$('btnMaximize').addEventListener('click', () => window.api.maximize());
$('btnClose').addEventListener('click', () => window.api.close());

/* ====== Keyboard Shortcuts ====== */
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    if (state.search) {
      searchInput.value = '';
      state.search = '';
      clearSearchBtn.style.display = 'none';
      applyFilterAndRender();
    } else if (state.detailsOpen) {
      toggleDetails(false);
    }
  }
  if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
    e.preventDefault();
    searchInput.focus();
    searchInput.select();
  }
  if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
    e.preventDefault();
    window.api.forceRefresh();
  }
  if (e.key === 'Delete' && state.selected && state.detailsOpen) {
    btnKill.click();
  }
});

/* ====== Helpers ====== */
function escHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function truncate(str, max) {
  if (!str) return '';
  return str.length > max ? str.slice(0, max) + '…' : str;
}

function getStatusClass(status) {
  if (!status) return 'status-other';
  const s = status.toLowerCase();
  if (s === 'running') return 'status-running';
  if (s === 'sleeping' || s === 'idle' || s === 'wait') return 'status-sleeping';
  if (s === 'stopped' || s === 'zombie') return 'status-stopped';
  return 'status-other';
}

function formatTime(started) {
  if (!started) return '—';
  try {
    const d = new Date(started);
    if (isNaN(d)) return started;
    const now = new Date();
    const diff = now - d;
    if (diff < 60000) return 'Just started';
    if (diff < 3600000) return `${Math.round(diff / 60000)}m ago`;
    if (diff < 86400000) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return d.toLocaleDateString();
  } catch {
    return started;
  }
}

/* ====== Startup Toggle ====== */
const startupToggle = $('startupToggle');
window.api.getStartupSetting().then(enabled => {
  startupToggle.checked = enabled;
}).catch(() => {});
startupToggle.addEventListener('change', async () => {
  const result = await window.api.setStartupSetting(startupToggle.checked);
  startupToggle.checked = result;
  showToast(
    result ? 'TaskInsight will run at startup' : 'Removed from startup',
    result ? 'success' : 'info'
  );
});

/* ====== Initial UI State ====== */
toggleDetails(false);
// Mark CPU column as sorted initially
document.querySelector('[data-col="cpu"]')?.classList.add('sorted');
