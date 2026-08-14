/* ---------- CONFIG ---------- */
const MACHINES_JSON = 'data/machines.json';
const CARDS_PER_BATCH = 60;   // Renderizado por lotes para evitar bloqueo
let   allMachines = [];
let   filtered    = [];

/* ---------- UTILS ---------- */
const qs    = (s, c = document) => c.querySelector(s);
const qsa   = (s, c = document) => c.querySelectorAll(s);
const delay = ms => new Promise(r => setTimeout(r, ms));

/* ---------- RENDERIZADO POR LOTES (ANTI-LAG) ---------- */
async function renderMachines(machines) {
    const grid = qs('#all-machines-container');
    grid.innerHTML = '';                       // Limpia anterior
    if (!machines.length) {
        grid.innerHTML = '<p class="no-machines">No se encontraron máquinas</p>';
        return;
    }

    const template = m => `
    <div class="machine-card"
         data-categories="${m.categories.join(' ').toLowerCase()}"
         data-difficulty="${m.difficulty.toLowerCase()}"
         data-keywords="${(m.name + ' ' + m.description + ' ' + m.platform + ' ' + m.categories.join(' ')).toLowerCase()}">
      <img src="${m.platformIcon}" alt="${m.platform}" class="machine-platform">
      <div class="machine-header">
        <img src="${m.icon}" alt="${m.name}" class="machine-icon">
        <div class="machine-header-info">
          <div class="machine-categories">
            ${m.categories.map(c => `<span class="machine-category ${c}">${c}</span>`).join('')}
          </div>
          <span class="machine-difficulty ${m.difficulty.toLowerCase()}">${m.difficulty}</span>
        </div>
      </div>
      <h3 class="machine-title">${m.name}</h3>
      <p class="machine-description">${m.description}</p>
      <div class="machine-meta">
        <span class="machine-date">${formatDate(m.date)}</span>
        ${m.status === 'Active'
            ? '<div class="machine-unavailable"><i class="fas fa-question-circle"></i> Unavailable</div>'
            : `<a href="${m.url}" class="machine-link">Writeup <i class="fas fa-external-link-alt"></i></a>`}
      </div>
    </div>`;

    let idx = 0;
    while (idx < machines.length) {
        const chunk = machines.slice(idx, idx + CARDS_PER_BATCH).map(template).join('');
        grid.insertAdjacentHTML('beforeend', chunk);
        idx += CARDS_PER_BATCH;
        await delay(16);          // Libera el hilo
    }
}

/* ---------- FILTRADO (CASE-INSENSITIVE) ---------- */
function filterNow() {
    const searchTerm = (qs('#search-input')?.value.trim().toLowerCase() || '');
    const activeCat  = qs('.filter-btn.active')?.dataset.filter || 'all';

    filtered = allMachines.filter(m => {
        const matchesSearch = !searchTerm ||
            m.name.toLowerCase().includes(searchTerm) ||
            m.description.toLowerCase().includes(searchTerm) ||
            m.platform.toLowerCase().includes(searchTerm) ||
            m.categories.some(c => c.toLowerCase().includes(searchTerm)) ||
            m.difficulty.toLowerCase().includes(searchTerm);   // <-- nuevo
        const matchesCat = (activeCat === 'all') ||
            m.categories.map(c => c.toLowerCase()).includes(activeCat.toLowerCase());
        return matchesSearch && matchesCat;
    });

    renderMachines(filtered);
}

/* ---------- INICIALIZACIÓN ---------- */
async function loadAllMachines() {
    try {
        const res = await fetch(MACHINES_JSON);
        allMachines = await res.json();
        filtered    = allMachines;
        renderMachines(filtered);
        initListeners();
    } catch (e) {
        qs('#all-machines-container').innerHTML =
            '<p class="error">Error al cargar las máquinas</p>';
    }
}

function initListeners() {
    // Buscador
    const searchInput = qs('#search-input');
    if (searchInput) {
        let t;                                      // debounce
        searchInput.addEventListener('input', () => {
            clearTimeout(t);
            t = setTimeout(filterNow, 200);
        });
    }
    // Botones de categoría
    qsa('.filter-btn').forEach(btn =>
        btn.addEventListener('click', e => {
            qsa('.filter-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            filterNow();
        })
    );
}

/* ---------- INDEX (últimas 4) ---------- */
async function loadLatestMachines() {
    try {
        const res = await fetch(MACHINES_JSON);
        const machines = await res.json();
        const latest = machines
            .sort((a, b) => new Date(b.date) - new Date(a.date))
            .slice(0, 4);
        renderLatest(latest);
    } catch (e) {
        qs('#machines-container').innerHTML =
            '<p class="error">Error al cargar máquinas</p>';
    }
}

function renderLatest(machines) {
    const container = qs('#machines-container');
    container.innerHTML = machines.map(m => `
    <div class="machine-card">
      <img src="${m.platformIcon}" alt="${m.platform}" class="machine-platform">
      <div class="machine-header">
        <img src="${m.icon}" alt="${m.name}" class="machine-icon">
        <div class="machine-header-info">
          <div class="machine-categories">
            ${m.categories.map(c => `<span class="machine-category ${c}">${c}</span>`).join('')}
          </div>
          <span class="machine-difficulty ${m.difficulty.toLowerCase()}">${m.difficulty}</span>
        </div>
      </div>
      <h3 class="machine-title">${m.name}</h3>
      <p class="machine-description">${m.description}</p>
      <div class="machine-meta">
        <span class="machine-date">${formatDate(m.date)}</span>
        ${m.status === 'Active'
            ? '<div class="machine-unavailable"><i class="fas fa-question-circle"></i> Unavailable</div>'
            : `<a href="${m.url}" class="machine-link">Writeup <i class="fas fa-external-link-alt"></i></a>`}
      </div>
    </div>`).join('');
}

/* ---------- UTILIDADES ---------- */
function formatDate(dateStr) {
    return new Date(dateStr).toLocaleDateString('es-ES',
        { day: '2-digit', month: 'short', year: 'numeric' });
}

/* ---------- ARRANQUE ---------- */
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname.includes('machines.html')) {
        loadAllMachines();
    } else {
        loadLatestMachines();
    }
});

/* ---------- CVE CONFIG ---------- */
const CVES_JSON = 'data/cves.json';
const CVES_PER_BATCH = 60;
let allCVEs   = [];
let cveFiltered = [];

/* ---------- CVE RENDER (BATCHED) ---------- */
async function renderCVEs(cves) {
    const grid = qs('#all-cves-container');
    if (!grid) return;
    grid.innerHTML = '';
    if (!cves.length) {
        grid.innerHTML = '<p class="no-machines">No se encontraron CVEs</p>';
        return;
    }

    const template = c => `
    <div class="machine-card cve-card"
         data-cve-categories="${c.technology.toLowerCase()} ${c.severity.toLowerCase()}"
         data-cve-keywords="${(c.cve_id + ' ' + c.vulnerability_name + ' ' + c.technology + ' ' + c.version + ' ' + c.severity).toLowerCase()}">
      <div class="machine-header">
        <img src="${c.icon}" alt="${c.technology}" class="machine-icon">
        <div class="machine-header-info">
          <div class="machine-categories">
            <span class="machine-category ${c.severity.toUpperCase()}">${c.severity}</span>
            <span class="machine-category" style="background:rgba(255,79,129,0.2);color:#ff4f81;">${c.technology}</span>
          </div>
          <span class="machine-difficulty">CVSS: ${c.cvss_score}</span>
        </div>
      </div>
      <h3 class="machine-title">${c.cve_id}</h3>
      <p class="machine-description">${c.vulnerability_name} — ${c.description}</p>
      <div class="machine-meta">
        <span class="machine-date">${formatDate(c.date)}</span>
        <a href="cve-detail.html?cve=${c.cve_id}" class="machine-link">View PoC <i class="fas fa-external-link-alt"></i></a>
      </div>
    </div>`;

    let idx = 0;
    while (idx < cves.length) {
        const chunk = cves.slice(idx, idx + CVES_PER_BATCH).map(template).join('');
        grid.insertAdjacentHTML('beforeend', chunk);
        idx += CVES_PER_BATCH;
        await delay(16);
    }
}

/* ---------- CVE FILTER ---------- */
function filterCVENow() {
    const searchTerm = (qs('#cve-search-input')?.value.trim().toLowerCase() || '');
    const activeCat  = qs('.filter-btn[data-cve-filter].active')?.dataset.cveFilter || 'all';

    cveFiltered = allCVEs.filter(c => {
        const matchesSearch = !searchTerm ||
            c.cve_id.toLowerCase().includes(searchTerm) ||
            c.vulnerability_name.toLowerCase().includes(searchTerm) ||
            c.technology.toLowerCase().includes(searchTerm) ||
            c.version.toLowerCase().includes(searchTerm) ||
            c.severity.toLowerCase().includes(searchTerm) ||
            c.description.toLowerCase().includes(searchTerm);
        const matchesCat = (activeCat === 'all') ||
            c.severity.toLowerCase() === activeCat.toLowerCase();
        return matchesSearch && matchesCat;
    });

    renderCVEs(cveFiltered);
}

/* ---------- CVE INIT ---------- */
async function loadAllCVEs() {
    try {
        const res = await fetch(CVES_JSON);
        allCVEs   = await res.json();
        cveFiltered = allCVEs;
        renderCVEs(cveFiltered);
        initCVEListeners();
    } catch (e) {
        const grid = qs('#all-cves-container');
        if (grid) grid.innerHTML = '<p class="error">Error al cargar los CVEs</p>';
    }
}

function initCVEListeners() {
    const searchInput = qs('#cve-search-input');
    if (searchInput) {
        let t;
        searchInput.addEventListener('input', () => {
            clearTimeout(t);
            t = setTimeout(filterCVENow, 200);
        });
    }
    qsa('.filter-btn[data-cve-filter]').forEach(btn =>
        btn.addEventListener('click', e => {
            qsa('.filter-btn[data-cve-filter]').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            filterCVENow();
        })
    );
}

/* ---------- INDEX (latest 4 CVEs) ---------- */
async function loadLatestCVEs() {
    try {
        const res   = await fetch(CVES_JSON);
        const cves  = await res.json();
        const latest = cves
            .sort((a, b) => new Date(b.date) - new Date(a.date))
            .slice(0, 4);
        renderLatestCVEs(latest);
    } catch (e) {
        const c = qs('#cves-container');
        if (c) c.innerHTML = '<p class="error">Error al cargar CVEs</p>';
    }
}

function renderLatestCVEs(cves) {
    const container = qs('#cves-container');
    if (!container) return;
    container.innerHTML = cves.map(c => `
    <div class="machine-card cve-card">
      <div class="machine-header">
        <img src="${c.icon}" alt="${c.technology}" class="machine-icon">
        <div class="machine-header-info">
          <div class="machine-categories">
            <span class="machine-category ${c.severity.toUpperCase()}">${c.severity}</span>
            <span class="machine-category" style="background:rgba(255,79,129,0.2);color:#ff4f81;">${c.technology}</span>
          </div>
          <span class="machine-difficulty">CVSS: ${c.cvss_score}</span>
        </div>
      </div>
      <h3 class="machine-title">${c.cve_id}</h3>
      <p class="machine-description">${c.vulnerability_name} — ${c.description}</p>
      <div class="machine-meta">
        <span class="machine-date">${formatDate(c.date)}</span>
        <a href="cve-detail.html?cve=${c.cve_id}" class="machine-link">View PoC <i class="fas fa-external-link-alt"></i></a>
      </div>
    </div>`).join('');
}

/* ---------- ROUTER UPDATE ---------- */
document.addEventListener('DOMContentLoaded', () => {
    const path = window.location.pathname;
    if (path.includes('machines.html')) {
        loadAllMachines();
    } else if (path.includes('cves.html')) {
        loadAllCVEs();
    } else if (path.includes('cve-detail.html')) {
        // handled by cve-renderer.js
    } else {
        loadLatestMachines();
        loadLatestCVEs();
    }
});