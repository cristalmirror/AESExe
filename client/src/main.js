const SERVER = 'https://localhost:8080';

const cuilInput = document.getElementById('cuil');
const textarea  = document.getElementById('textarea-data');
const btnEnviar = document.getElementById('btn-enviar');
const fileInput = document.getElementById('fileInput');

function getCipher() {
    const sel = document.querySelector('input[name="cipher"]:checked');
    return sel ? sel.value.toLowerCase() : null;
}

async function toBase64(file) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
}

async function encrypt() {
    const cuil   = cuilInput.value.trim();
    const data   = textarea.value.trim();
    const cipher = getCipher();

    if (!cuil || !data || !cipher) {
        alert('Complete CUIL, texto y seleccione un cifrado.');
        return;
    }

    const res = await fetch(`${SERVER}/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cuil, data, cipher })
    });

    if (!res.ok) { alert(`Error del servidor: ${res.status}`); return; }

    const blob = await res.blob();
    const ext  = cipher === 'chacha20' ? 'cc20' : 'aes';
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `key_${cuil}.${ext}`;
    a.click();
    URL.revokeObjectURL(a.href);
    textarea.value = '';
}

async function decrypt(keyFile) {
    const cuil   = cuilInput.value.trim();
    const cipher = getCipher();

    if (!cuil || !cipher) {
        alert('Complete el CUIL y seleccione un cifrado.');
        return;
    }

    const key = await toBase64(keyFile);

    const res = await fetch(`${SERVER}/decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cuil, key, cipher })
    });

    if (!res.ok) { alert(`Error del servidor: ${res.status}`); return; }

    textarea.value = await res.text();
}

btnEnviar.addEventListener('click', encrypt);
fileInput.addEventListener('change', e => {
    if (e.target.files[0]) decrypt(e.target.files[0]);
});
