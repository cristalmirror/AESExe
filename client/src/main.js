const SERVER = 'https://192.168.1.35:8080';

const cuilInput = document.getElementById('cuil');
const textarea  = document.getElementById('textarea-data');
const btnEnviar = document.getElementById('btn-enviar');
const btnBuscar = document.getElementById('btn-buscar');
const fileInput = document.getElementById('fileInput');

function getMode() {
    const checked = document.querySelector('input[name="mode"]:checked');
    return checked ? checked.value : null;
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
    const algo = document.getElementById('algo').value;

    if (!cuil || !data) {
        alert('Complete el CUIL y las contraseñas.');
        return;
    }

    const res = await fetch(`${SERVER}/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cuil, data, algo })
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
    const algo = document.getElementById('algo').value;

    if (!cuil) {
        alert('Complete el CUIL.');
        return;
    }

    const key = await toBase64(keyFile);

    const res = await fetch(`${SERVER}/decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cuil, key, algo })
    });

    if (!res.ok) { alert(`Error del servidor: ${res.status}`); return; }

    const plaintext = await res.text();
    textarea.style.display = '';
    textarea.value = plaintext;
}

function setMode(mode) {
    const isCipher = mode === 'cipher';
    textarea.style.display  = isCipher ? '' : 'none';
    btnEnviar.style.display = isCipher ? '' : 'none';
    btnBuscar.style.display = isCipher ? 'none' : '';
}

document.querySelector('input[name="mode"][value="cipher"]').addEventListener('change',   () => setMode('cipher'));
document.querySelector('input[name="mode"][value="decipher"]').addEventListener('change', () => setMode('decipher'));

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
