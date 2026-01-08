(function(){
  if (typeof marked === 'undefined') return console.error('marked no cargado');
  marked.setOptions({breaks:true,gfm:true}); // sin highlight

  async function loadWriteup(){
    const contentDiv   = document.getElementById('markdown-content');
    const machineName  = location.pathname.split('/').slice(-2,-1)[0]; // carpeta
    const iconSrc      = `../../assets/icons/${machineName.toLowerCase()}.png`;

    document.getElementById('machine-name').textContent = machineName + ' – Writeup';
    document.title = machineName + ' – Writeup';
    document.getElementById('machine-icon').src = iconSrc;

    try {
      const res = await fetch('index.md');
      if (!res.ok) throw new Error(res.status + ' ' + res.statusText);
      const md  = await res.text();
      contentDiv.innerHTML = marked.parse(md);
    } catch (e) {
      console.error(e);
      contentDiv.innerHTML =
        `<p style="text-align:center;color:#ff4f81;padding:2rem;">
          Error al cargar <strong>index.md</strong><br>${e}
        </p>`;
    }
  }

  document.addEventListener('DOMContentLoaded', loadWriteup);
})();