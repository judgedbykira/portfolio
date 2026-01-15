(() => {
  const btn = document.createElement('button');
  btn.id = 'btn-subir';
  btn.innerHTML = '↑';
  btn.style.cssText = `
    position:fixed; bottom:20px; right:20px; width:56px; height:56px;
    border:none; border-radius:50%; background:rgba(190, 70, 104, 0.3); color:#fff;
    font-size:22px; cursor:pointer; opacity:0; visibility:hidden;
    transition:opacity .3s, visibility .3s; z-index:9999;
  `;
  document.body.appendChild(btn);

  const mostrar = () => {
    if (window.scrollY > 200) {
      btn.style.opacity = '1';
      btn.style.visibility = 'visible';
    } else {
      btn.style.opacity = '0';
      btn.style.visibility = 'hidden';
    }
  };

  btn.addEventListener('click', () => window.scrollTo({top:0, behavior:'smooth'}));
  window.addEventListener('scroll', mostrar);
})();