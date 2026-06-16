chrome.runtime.onMessage.addListener(msg => {
    if (msg.type !== 'AESEXE_DOWNLOAD_KEY') return;
    chrome.downloads.download({
        url: `data:application/octet-stream;base64,${msg.keyBase64}`,
        filename: msg.filename,
        conflictAction: 'overwrite',
        saveAs: false
    });
});
