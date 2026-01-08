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
            : `<a href="${m.url}" class="machine-link" target="_blank">Writeup <i class="fas fa-external-link-alt"></i></a>`}
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
            : `<a href="${m.url}" class="machine-link" target="_blank">Writeup <i class="fas fa-external-link-alt"></i></a>`}
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