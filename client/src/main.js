const SERVER = 'https://localhost:8080';

const cuilInput = document.getElementById('cuil');
const textarea  = document.getElementById('textarea-data');
const btnEnviar = document.getElementById('btn-enviar');
const btnBuscar = document.getElementById('btn-buscar');
const fileInput = document.getElementById('fileInput');

function getMode() {
    if (document.querySelector('input[name="decipher"]:checked')) return 'decipher';
    if (document.querySelector('input[name="cipher"]:checked'))   return 'cipher';
    return null;
}

async function toBase64(file) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
}

async function encrypt() {
    const cuil = cuilInput.value.trim();
    const data = textarea.value.trim();

    if (!cuil || !data) {
        alert('Complete el CUIL y las contraseñas.');
        return;
    }

    const res = await fetch(`${SERVER}/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cuil, data })
    });

    if (!res.ok) { alert(`Error del servidor: ${res.status}`); return; }

    const blob = await res.blob();
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `key_${cuil}.bin`;
    a.click();
    URL.revokeObjectURL(a.href);
    textarea.value = '';
}

async function decrypt(keyFile) {
    const cuil = cuilInput.value.trim();

    if (!cuil) {
        alert('Complete el CUIL.');
        return;
    }

    const key = await toBase64(keyFile);

    const res = await fetch(`${SERVER}/decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cuil, key })
    });

    if (!res.ok) { alert(`Error del servidor: ${res.status}`); return; }

    const { passwords, newKey } = await res.json();
    textarea.value = passwords;

    window.postMessage({
        type: 'AESEXE_DOWNLOAD_KEY',
        keyBase64: newKey,
        filename: `key_${cuil}.bin`
    }, '*');
}

function setMode(mode) {
    const isCipher = mode === 'cipher';
    textarea.style.display  = isCipher ? '' : 'none';
    btnEnviar.style.display = isCipher ? '' : 'none';
    btnBuscar.style.display = isCipher ? 'none' : '';
}

document.querySelector('input[name="cipher"]').addEventListener('change',   () => setMode('cipher'));
document.querySelector('input[name="decipher"]').addEventListener('change', () => setMode('decipher'));

btnEnviar.addEventListener('click', () => {
    const mode = getMode();
    if (mode === 'cipher')        encrypt();
    else if (mode === 'decipher') fileInput.click();
    else                          alert('Seleccione un modo.');
});

fileInput.addEventListener('change', e => {
    if (getMode() !== 'decipher') { alert('Seleccione "Buscar Contraseñas".'); return; }
    if (e.target.files[0]) decrypt(e.target.files[0]);
});
