const analyses = [
  { name: 'camera-gw_2.8.1.bin', vendor: 'OpenCam · rev 2.8.1', format: 'SquashFS', arch: 'MIPS32', status: 'Complete', findings: 4, updated: '12 min ago', tone: 'complete' },
  { name: 'router-rv34_1.4.0.img', vendor: 'OpenRouter · rev 1.4.0', format: 'UBI / UBIFS', arch: 'ARM32', status: 'Emulating', findings: 3, updated: 'Running', tone: 'running' },
  { name: 'gateway-mips_0.9.7.trx', vendor: 'EdgeLab · rev 0.9.7', format: 'TRX / CramFS', arch: 'MIPS32', status: 'Complete', findings: 2, updated: 'Yesterday', tone: 'complete' },
  { name: 'sensor-hub_3.1.2.bin', vendor: 'OpenSense · rev 3.1.2', format: 'SquashFS', arch: 'ARM64', status: 'Complete', findings: 1, updated: 'Oct 28', tone: 'complete' },
  { name: 'mesh-node_5.0.0.img', vendor: 'MeshLab · rev 5.0.0', format: 'JFFS2', arch: 'ARM32', status: 'Queued', findings: 0, updated: 'Oct 27', tone: 'queued' },
  { name: 'nas-lite_2.2.0.bin', vendor: 'OpenStore · rev 2.2.0', format: 'SquashFS', arch: 'x86_64', status: 'Complete', findings: 2, updated: 'Oct 24', tone: 'complete' },
  { name: 'access-point_1.1.5.bin', vendor: 'LibreAP · rev 1.1.5', format: 'UBI / UBIFS', arch: 'MIPS32', status: 'Complete', findings: 0, updated: 'Oct 22', tone: 'complete' },
  { name: 'doorbell-cam_4.3.0.img', vendor: 'OpenCam · rev 4.3.0', format: 'SquashFS', arch: 'ARM64', status: 'Complete', findings: 0, updated: 'Oct 20', tone: 'complete' }
];

const findings = [
  { severity: 'High', title: 'Hardcoded credential candidate', cwe: 'CWE-798', file: '/etc/config/auth', binary: 'camera-gw_2.8.1.bin', evidence: 'Credential-like string found in a plaintext configuration file. Value redacted in this report.', category: 'Secrets' },
  { severity: 'High', title: 'Unbounded copy in request path', cwe: 'CWE-120', file: '/usr/sbin/httpd', binary: 'router-rv34_1.4.0.img', evidence: 'Static pattern indicates a potentially unsafe copy near request parsing. Reachability is unconfirmed.', category: 'Memory safety' },
  { severity: 'Medium', title: 'Unsafe string operation', cwe: 'CWE-120', file: '/usr/sbin/httpd', binary: 'router-rv34_1.4.0.img', evidence: 'Boundedness of the destination buffer could not be established in the selected code path.', category: 'Memory safety' },
  { severity: 'Medium', title: 'PIE not enabled', cwe: 'CWE-1210', file: '/usr/bin/diag', binary: 'gateway-mips_0.9.7.trx', evidence: 'ELF type indicates a fixed-address executable; address randomization support is absent.', category: 'Hardening' },
  { severity: 'Medium', title: 'Legacy digest algorithm reference', cwe: 'CWE-328', file: '/usr/lib/libauth.so', binary: 'camera-gw_2.8.1.bin', evidence: 'Reference to a legacy digest API observed. Usage and security impact require review.', category: 'Cryptography' },
  { severity: 'Low', title: 'Stack canary not detected', cwe: 'CWE-693', file: '/usr/bin/diag', binary: 'gateway-mips_0.9.7.trx', evidence: 'No stack-protector reference found in this binary; static results may be incomplete.', category: 'Hardening' },
  { severity: 'Low', title: 'World-readable configuration', cwe: 'CWE-732', file: '/etc/config/network', binary: 'camera-gw_2.8.1.bin', evidence: 'Sample filesystem metadata marks this configuration readable by all users.', category: 'Permissions' },
  { severity: 'Low', title: 'Deprecated TLS API reference', cwe: 'CWE-327', file: '/usr/lib/libsslwrap.so', binary: 'sensor-hub_3.1.2.bin', evidence: 'Deprecated cryptographic API symbol present; active usage is not established.', category: 'Cryptography' }
];

const binaries = [
  ['usr/sbin/httpd', 'MIPS32 LE', true, true, 'Partial', false],
  ['usr/bin/diag', 'MIPS32 LE', true, false, 'None', false],
  ['usr/bin/netd', 'MIPS32 LE', true, true, 'Full', true],
  ['usr/lib/libauth.so', 'MIPS32 LE', true, true, 'Full', true],
  ['usr/sbin/upgrade', 'MIPS32 LE', false, false, 'None', false]
];

const treeItems = [
  { depth: 0, name: 'etc', type: 'folder', meta: '34 files' },
  { depth: 1, name: 'config', type: 'folder', meta: '12 files' },
  { depth: 2, name: 'auth', type: 'file', meta: '2.1 KB', selected: true },
  { depth: 2, name: 'network', type: 'file', meta: '1.4 KB' },
  { depth: 0, name: 'usr', type: 'folder', meta: '184 files' },
  { depth: 1, name: 'sbin', type: 'folder', meta: '28 files' },
  { depth: 2, name: 'httpd', type: 'binary', meta: 'ELF · MIPS32' },
  { depth: 2, name: 'upgrade', type: 'binary', meta: 'ELF · MIPS32' },
  { depth: 1, name: 'bin', type: 'folder', meta: '42 files' },
  { depth: 2, name: 'diag', type: 'binary', meta: 'ELF · MIPS32' },
  { depth: 0, name: 'bin', type: 'folder', meta: '18 files' },
  { depth: 0, name: 'www', type: 'folder', meta: '26 files' }
];

const severityClass = (severity) => severity.toLowerCase();
const findingCount = (count) => count === 0 ? '<span class="finding-zero">—</span>' : `<span class="finding-number">${count}</span>`;
const analysisRow = (item) => `<td><span class="firmware-name">${item.name}</span><span class="firmware-vendor">${item.vendor}</span></td><td><span class="format-tag">${item.arch}</span></td><td><span class="status-tag ${item.tone}"><i></i>${item.status}</span></td><td>${findingCount(item.findings)}</td><td class="updated-cell">${item.updated}</td><td class="row-arrow">→</td>`;

document.querySelector('#recent-rows').innerHTML = analyses.slice(0, 4).map((item) => `<tr>${analysisRow(item)}</tr>`).join('');
document.querySelector('#analysis-rows').innerHTML = analyses.map((item) => `<tr data-search="${`${item.name} ${item.arch} ${item.format}`.toLowerCase()}">${analysisRow(item)}</tr>`).join('');
document.querySelector('#file-tree').innerHTML = treeItems.map((item) => `<button class="tree-item depth-${item.depth} ${item.selected ? 'selected' : ''}" data-file="${item.name}"><span class="tree-chevron">${item.type === 'folder' ? '⌄' : ''}</span><span class="tree-icon ${item.type}">${item.type === 'folder' ? '▰' : item.type === 'binary' ? '▣' : '▤'}</span><span class="tree-name">${item.name}</span><span class="tree-meta">${item.meta}</span></button>`).join('');
document.querySelector('#binary-rows').innerHTML = binaries.map((binary) => `<tr><td class="binary-name">${binary[0]}</td><td>${binary[1]}</td>${binary.slice(2).map((value, index) => `<td><span class="matrix-value ${value === true ? 'enabled' : value === false ? 'disabled' : 'partial'}">${value === true ? '✓' : value === false ? '×' : '◐'}</span></td>`).join('')}</tr>`).join('');

function renderFindings(filter = 'all') {
  const filtered = filter === 'all' ? findings : findings.filter((finding) => finding.severity === filter);
  document.querySelector('#finding-list').innerHTML = filtered.map((finding) => `<article class="finding-card"><div class="finding-card-top"><span class="severity-tag ${severityClass(finding.severity)}"><i></i>${finding.severity}</span><span class="cwe-tag">${finding.cwe}</span><span class="category-tag">${finding.category}</span></div><h2>${finding.title}</h2><p>${finding.evidence}</p><div class="finding-meta"><span>${finding.binary}</span><span class="meta-sep">/</span><code>${finding.file}</code><button class="copy-finding" data-copy="${finding.cwe}">Copy CWE</button></div></article>`).join('') || '<div class="empty-state">No findings in this severity band.</div>';
}
renderFindings();

const views = ['overview', 'analyses', 'findings', 'artifacts', 'environment'];
function showView(view) {
  if (!views.includes(view)) return;
  document.querySelectorAll('.view').forEach((section) => { section.hidden = section.id !== `${view}-view`; section.classList.toggle('active-view', section.id === `${view}-view`); });
  document.querySelectorAll('.nav-item').forEach((button) => button.classList.toggle('active', button.dataset.view === view));
  const title = view === 'overview' ? 'Overview' : view === 'environment' ? 'Sandbox status' : view[0].toUpperCase() + view.slice(1);
  document.querySelector('#breadcrumb-current').textContent = title;
  document.querySelector('#sidebar').classList.remove('sidebar-open');
  history.replaceState(null, '', `#${view}`);
}

document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => showView(button.dataset.view)));
document.querySelectorAll('[data-open-view]').forEach((button) => button.addEventListener('click', () => showView(button.dataset.openView)));
document.querySelectorAll('.filter-chip').forEach((button) => button.addEventListener('click', () => {
  document.querySelectorAll('.filter-chip').forEach((chip) => chip.classList.toggle('selected', chip === button));
  renderFindings(button.dataset.filter);
}));

document.querySelector('#analysis-search').addEventListener('input', (event) => {
  const query = event.target.value.trim().toLowerCase();
  document.querySelectorAll('#analysis-rows tr').forEach((row) => { row.hidden = !row.dataset.search.includes(query); });
});

document.querySelector('#file-tree').addEventListener('click', (event) => {
  const item = event.target.closest('.tree-item');
  if (!item) return;
  document.querySelectorAll('.tree-item').forEach((row) => row.classList.toggle('selected', row === item));
  document.querySelector('.detail-kicker').textContent = 'SELECTED ARTIFACT';
  document.querySelector('.binary-detail > b').textContent = item.dataset.file;
});

let toastTimer;
function showToast(message) {
  const toast = document.querySelector('#toast');
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('visible'), 2600);
}

document.querySelector('#finding-list').addEventListener('click', async (event) => {
  const button = event.target.closest('.copy-finding');
  if (!button) return;
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
    showToast(`${button.dataset.copy} copied`);
  } catch {
    showToast(button.dataset.copy);
  }
});

const dialog = document.querySelector('#analysis-dialog');
const openDialog = () => dialog.showModal();
document.querySelector('#new-analysis').addEventListener('click', openDialog);
document.querySelector('#new-analysis-list').addEventListener('click', openDialog);
document.querySelector('#mobile-menu').addEventListener('click', () => document.querySelector('#sidebar').classList.toggle('sidebar-open'));
document.querySelector('#dismiss-banner').addEventListener('click', () => document.querySelector('.demo-banner').remove());
document.querySelector('#firmware-file').addEventListener('change', (event) => {
  const file = event.target.files[0];
  document.querySelector('#upload-label').textContent = file ? file.name : 'Choose a firmware image';
});
document.querySelector('#analysis-form').addEventListener('submit', (event) => {
  event.preventDefault();
  dialog.close();
  event.currentTarget.reset();
  document.querySelector('#upload-label').textContent = 'Choose a firmware image';
  showToast('Demo only: no file was uploaded or analyzed.');
});

const initialView = location.hash.slice(1);
if (views.includes(initialView)) showView(initialView);