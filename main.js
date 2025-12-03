// Cargar últimas 4 máquinas desde JSON
async function loadLatestMachines() {
    try {
        const response = await fetch('data/machines.json');
        if (!response.ok) throw new Error('Error al cargar máquinas');
        
        const machines = await response.json();
        
        // Ordenar por fecha (más recientes primero) y tomar 4
        const latestMachines = machines
            .sort((a, b) => new Date(b.date) - new Date(a.date))
            .slice(0, 4);
        
        const container = document.getElementById('machines-container');
        
        if (latestMachines.length === 0) {
            container.innerHTML = '<p class="no-machines">No hay máquinas disponibles</p>';
            return;
        }
        
        container.innerHTML = latestMachines.map(machine => `
            <div class="machine-card" data-categories="${machine.categories.join(' ')}" 
                 data-description="${machine.description.toLowerCase()}">
                <img src="${machine.platformIcon}" alt="${machine.platform}" class="machine-platform">
                <div class="machine-header">
                    <img src="${machine.icon}" alt="${machine.name}" class="machine-icon">
                    <div class="machine-header-info">
                        <div class="machine-categories">
                            ${machine.categories.map(cat => `<span class="machine-category ${cat}">${cat}</span>`).join('')}
                        </div>
                        <span class="machine-difficulty ${machine.difficulty.toLowerCase()}">${machine.difficulty}</span>
                    </div>
                </div>
                <h3 class="machine-title">${machine.name}</h3>
                <p class="machine-description">${machine.description}</p>
                <div class="machine-meta">
                    <span class="machine-date">${formatDate(machine.date)}</span>
                    ${machine.status === 'Active' 
                        ? '<div class="machine-unavailable"><i class="fas fa-question-circle"></i> Unavailable</div>' 
                        : `<a href="${machine.url}" class="machine-link" target="_blank">
                                Writeup <i class="fas fa-external-link-alt"></i>
                           </a>`
                    }
                </div>
            </div>
        `).join('');
        
    } catch (error) {
        console.error('Error cargando máquinas:', error);
        document.getElementById('machines-container').innerHTML = 
            '<p class="error">Error al cargar las máquinas</p>';
    }
}

// Formatear fecha al español
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('es-ES', { 
        day: '2-digit', 
        month: 'short', 
        year: 'numeric' 
    });
}

// Buscador y filtros combinados para machines.html
let allMachinesData = []; // Almacena todas las máquinas

async function loadAllMachines() {
    try {
        const response = await fetch('data/machines.json');
        allMachinesData = await response.json();
        
        const container = document.getElementById('all-machines-container');
        
        // Inicializar buscador
        initializeSearch();
        
        // Mostrar todas las máquinas inicialmente
        renderMachines(allMachinesData);
        
    } catch (error) {
        console.error('Error cargando máquinas:', error);
        document.getElementById('all-machines-container').innerHTML = 
            '<p class="error">Error al cargar las máquinas</p>';
    }
}

function renderMachines(machines) {
    const container = document.getElementById('all-machines-container');
    
    if (machines.length === 0) {
        container.innerHTML = '<p class="no-machines">No se encontraron máquinas</p>';
        return;
    }
    
    container.innerHTML = machines.map(machine => `
        <div class="machine-card" data-categories="${machine.categories.join(' ')}" 
             data-description="${machine.description.toLowerCase()}">
            <img src="${machine.platformIcon}" alt="${machine.platform}" class="machine-platform">
            <div class="machine-header">
                <img src="${machine.icon}" alt="${machine.name}" class="machine-icon">
                <div class="machine-header-info">
                    <div class="machine-categories">
                        ${machine.categories.map(cat => `<span class="machine-category ${cat}">${cat}</span>`).join('')}
                    </div>
                    <span class="machine-difficulty ${machine.difficulty.toLowerCase()}">${machine.difficulty}</span>
                </div>
            </div>
            <h3 class="machine-title">${machine.name}</h3>
            <p class="machine-description">${machine.description}</p>
            <div class="machine-meta">
                <span class="machine-date">${formatDate(machine.date)}</span>
                ${machine.status === 'Active' 
                    ? '<div class="machine-unavailable"><i class="fas fa-question-circle"></i> Unavailable</div>' 
                    : `<a href="${machine.url}" class="machine-link" target="_blank">
                            Writeup <i class="fas fa-external-link-alt"></i>
                       </a>`
                }
            </div>
        </div>
    `).join('');
    
    // Re-inicializar filtros después de renderizar
    initializeFilters();
}

function initializeSearch() {
    const searchInput = document.getElementById('search-input');
    if (!searchInput) return;
    
    searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        filterMachines(searchTerm);
    });
}

function filterMachines(searchTerm = '') {
    let filteredMachines = allMachinesData;
    
    // Aplicar filtro de búsqueda
    if (searchTerm) {
        filteredMachines = filteredMachines.filter(machine => 
            machine.name.toLowerCase().includes(searchTerm) ||
            machine.description.toLowerCase().includes(searchTerm) ||
            machine.categories.some(cat => cat.toLowerCase().includes(searchTerm)) ||
            machine.platform.toLowerCase().includes(searchTerm)
        );
    }
    
    // Aplicar filtro de categoría
    const activeCategory = document.querySelector('.filter-btn.active')?.dataset.filter;
    if (activeCategory && activeCategory !== 'all') {
        filteredMachines = filteredMachines.filter(machine => 
            machine.categories.includes(activeCategory)
        );
    }
    
    renderMachines(filteredMachines);
}

function initializeFilters() {
    const filterButtons = document.querySelectorAll('.filter-btn');
    
    filterButtons.forEach(button => {
        button.addEventListener('click', () => {
            filterButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            
            const searchTerm = document.getElementById('search-input')?.value.toLowerCase() || '';
            filterMachines(searchTerm);
        });
    });
}

// Inicializar cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', () => {
    // Cargar últimas 4 en index.html
    if (!window.location.pathname.includes('machines.html')) {
        loadLatestMachines();
    } else {
        // Cargar todas en machines.html
        loadAllMachines();
    }
});