window.addEventListener('message', event => {
    if (event.source !== window) return;
    if (event.data?.type !== 'AESEXE_DOWNLOAD_KEY') return;
    chrome.runtime.sendMessage(event.data);
});
