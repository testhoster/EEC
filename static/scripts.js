// Global state
let currentService = 'text';
let encryptedImageData = null;
let decryptedImageData = null;

// Page navigation
function showPage(pageId) {
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('visible');
    });
    document.getElementById(pageId).classList.add('visible');
}

// Service tab switching
function showService(service) {
    currentService = service;
    
    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.getElementById(`tab${service.charAt(0).toUpperCase() + service.slice(1)}`).classList.add('active');
    
    // Show/hide service cards
    document.getElementById('textService').classList.toggle('hidden', service !== 'text');
    document.getElementById('imageService').classList.toggle('hidden', service !== 'image');
}

// Login functionality
async function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const msgEl = document.getElementById('loginMsg');
    
    if (!username || !password) {
        msgEl.textContent = 'Please enter username and password';
        return;
    }
    
    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const result = await response.json();
        
        if (result.success) {
            msgEl.textContent = '';
            showPage('eccPage');
        } else {
            msgEl.textContent = result.message || 'Invalid credentials';
        }
    } catch (error) {
        msgEl.textContent = 'Connection error. Please try again.';
        console.error('Login error:', error);
    }
}

// Logout functionality
async function logout() {
    try {
        await fetch('/logout', { method: 'POST' });
        showPage('loginPage');
        
        // Clear all displays
        document.getElementById('eccStatus').innerHTML = '';
        document.getElementById('encryptedText').innerHTML = '';
        document.getElementById('decryptedText').innerHTML = '';
        document.getElementById('imageEncryptLog').innerHTML = '';
        
        // Reset form values
        document.getElementById('plainText').value = '';
        document.getElementById('cipherInput').value = '';
        document.getElementById('encFileBase64').value = '';
        document.getElementById('imageFile').value = '';
        
        // Reset global state
        encryptedImageData = null;
        decryptedImageData = null;
        
    } catch (error) {
        console.error('Logout error:', error);
    }
}

// ECC Key Generation
async function generateKeys() {
    const statusEl = document.getElementById('eccStatus');
    const loadingEl = document.getElementById('loadingAnim');
    
    loadingEl.classList.remove('hidden');
    statusEl.innerHTML = '';
    
    try {
        const response = await fetch('/generate-keys', { method: 'POST' });
        const result = await response.json();
        
        loadingEl.classList.add('hidden');
        
        if (result.success) {
            statusEl.innerHTML = `
                <div style="color: #00e676; margin-bottom: 15px;">✅ ECC Key Pairs Generated Successfully</div>
                <div style="color: #00b0ff; margin-bottom: 10px;"><strong>Node A Public Key:</strong></div>
                <div style="color: #bbb; font-size: 12px; word-break: break-all; margin-bottom: 15px;">${result.node_A_public}</div>
                <div style="color: #00b0ff; margin-bottom: 10px;"><strong>Node B Public Key:</strong></div>
                <div style="color: #bbb; font-size: 12px; word-break: break-all;">${result.node_B_public}</div>
            `;
        } else {
            statusEl.innerHTML = '<div style="color: #ff1744;">❌ Key generation failed</div>';
        }
    } catch (error) {
        loadingEl.classList.add('hidden');
        statusEl.innerHTML = '<div style="color: #ff1744;">❌ Network error during key generation</div>';
        console.error('Key generation error:', error);
    }
}

// Establish Shared Secret
async function establishSecret() {
    const statusEl = document.getElementById('eccStatus');
    const loadingEl = document.getElementById('loadingAnim');
    
    loadingEl.classList.remove('hidden');
    
    try {
        const response = await fetch('/establish-secret', { method: 'POST' });
        const result = await response.json();
        
        loadingEl.classList.add('hidden');
        
        if (result.success) {
            const currentContent = statusEl.innerHTML;
            statusEl.innerHTML = currentContent + `
                <div style="border-top: 1px solid #00e676; margin-top: 20px; padding-top: 20px;">
                    <div style="color: #00e676; margin-bottom: 10px;">🔐 Shared Secret Established</div>
                    <div style="color: #bbb;">Keys Match: <span style="color: ${result.keys_match ? '#00e676' : '#ff1744'}">${result.keys_match ? 'YES' : 'NO'}</span></div>
                    <div style="color: #bbb;">AES Key Length: <span style="color: #00e676">${result.symmetric_key_length} bytes</span></div>
                    <div style="color: #e91e63; margin-top: 15px; text-align: center;">🚀 Ready for encryption services!</div>
                </div>
            `;
            
            // Auto-navigate to services page after 2 seconds
            setTimeout(() => {
                showPage('servicePage');
            }, 2000);
        } else {
            statusEl.innerHTML += '<div style="color: #ff1744; margin-top: 15px;">❌ Failed to establish shared secret</div>';
        }
    } catch (error) {
        loadingEl.classList.add('hidden');
        statusEl.innerHTML += '<div style="color: #ff1744; margin-top: 15px;">❌ Network error during secret establishment</div>';
        console.error('Secret establishment error:', error);
    }
}

// Text Encryption
async function encryptText() {
    const plainText = document.getElementById('plainText').value;
    const resultEl = document.getElementById('encryptedText');
    
    if (!plainText.trim()) {
        resultEl.innerHTML = '<div style="color: #ff1744;">Please enter text to encrypt</div>';
        return;
    }
    
    try {
        const response = await fetch('/encrypt-text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: plainText })
        });
        
        const result = await response.json();
        
        if (result.success) {
            resultEl.innerHTML = `
                <div style="color: #00e676; margin-bottom: 10px;">🔒 Text Encrypted Successfully</div>
                <div style="color: #00b0ff; margin-bottom: 5px;"><strong>Encrypted (Hex):</strong></div>
                <div style="color: #bbb; font-size: 12px; word-break: break-all; margin-bottom: 15px; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 8px;">${result.encrypted_hex}</div>
                <div style="color: #00b0ff; margin-bottom: 5px;"><strong>Encrypted (Base64):</strong></div>
                <div style="color: #bbb; font-size: 12px; word-break: break-all; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 8px;">${result.encrypted_b64}</div>
            `;
        } else {
            resultEl.innerHTML = '<div style="color: #ff1744;">❌ Encryption failed</div>';
        }
    } catch (error) {
        resultEl.innerHTML = '<div style="color: #ff1744;">❌ Network error during encryption</div>';
        console.error('Text encryption error:', error);
    }
}

// Text Decryption
async function decryptText() {
    const cipherInput = document.getElementById('cipherInput').value.trim();
    const resultEl = document.getElementById('decryptedText');
    
    if (!cipherInput) {
        resultEl.innerHTML = '<div style="color: #ff1744;">Please enter encrypted hex data</div>';
        return;
    }
    
    try {
        const response = await fetch('/decrypt-text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ encrypted_hex: cipherInput })
        });
        
        const result = await response.json();
        
        if (result.success) {
            resultEl.innerHTML = `
                <div style="color: #00e676; margin-bottom: 10px;">🔓 Text Decrypted Successfully</div>
                <div style="color: #00b0ff; margin-bottom: 5px;"><strong>Original Message:</strong></div>
                <div style="color: #fff; background: rgba(0,230,118,0.1); padding: 15px; border-radius: 8px; border-left: 4px solid #00e676;">${result.decrypted_text}</div>
            `;
        } else {
            resultEl.innerHTML = `<div style="color: #ff1744;">❌ Decryption failed: ${result.message || 'Invalid data'}</div>`;
        }
    } catch (error) {
        resultEl.innerHTML = '<div style="color: #ff1744;">❌ Network error during decryption</div>';
        console.error('Text decryption error:', error);
    }
}

// Image Encryption
async function encryptImage() {
    const fileInput = document.getElementById('imageFile');
    const resultEl = document.getElementById('imageEncryptLog');
    
    if (!fileInput.files || !fileInput.files[0]) {
        resultEl.innerHTML = '<div style="color: #ff1744;">Please select an image file</div>';
        return;
    }
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    
    try {
        resultEl.innerHTML = '<div style="color: #00b0ff;">🔄 Encrypting image...</div>';
        
        const response = await fetch('/encrypt-image', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
            encryptedImageData = result.encrypted_base64;
            const fileName = fileInput.files[0].name;
            const fileSize = Math.round(fileInput.files[0].size / 1024);
            
            resultEl.innerHTML = `
                <div style="color: #00e676; margin-bottom: 10px;">🔒 Image Encrypted Successfully</div>
                <div style="color: #bbb; margin-bottom: 10px;">
                    <strong>File:</strong> ${fileName} (${fileSize} KB)<br>
                    <strong>Encrypted Size:</strong> ${Math.round(encryptedImageData.length * 0.75 / 1024)} KB
                </div>
                <div style="color: #00b0ff; margin-bottom: 5px;"><strong>Encrypted Data:</strong></div>
                <div style="color: #bbb; font-size: 11px; word-break: break-all; max-height: 100px; overflow-y: auto; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 8px;">${encryptedImageData.substring(0, 200)}...</div>
            `;
        } else {
            resultEl.innerHTML = `<div style="color: #ff1744;">❌ Image encryption failed: ${result.message || 'Unknown error'}</div>`;
        }
    } catch (error) {
        resultEl.innerHTML = '<div style="color: #ff1744;">❌ Network error during image encryption</div>';
        console.error('Image encryption error:', error);
    }
}

// Copy encrypted base64 to clipboard
function copyEncBase64() {
    if (!encryptedImageData) {
        alert('No encrypted data available');
        return;
    }
    
    navigator.clipboard.writeText(encryptedImageData).then(() => {
        // Show temporary feedback
        const btn = event.target;
        const originalText = btn.textContent;
        btn.textContent = '✅ Copied!';
        btn.style.background = '#00e676';
        
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '';
        }, 2000);
    }).catch(err => {
        console.error('Copy failed:', err);
        alert('Copy failed. Please copy manually from the encrypted data field.');
    });
}

// Download encrypted file
function downloadEncFile() {
    if (!encryptedImageData) {
        alert('No encrypted data available');
        return;
    }
    
    const blob = new Blob([encryptedImageData], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'encrypted_image.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Image Decryption
async function decryptImage() {
    const encFileBase64 = document.getElementById('encFileBase64').value.trim();
    const resultEl = document.getElementById('imageEncryptLog');
    
    if (!encFileBase64) {
        resultEl.innerHTML += '<div style="color: #ff1744; margin-top: 15px;">Please enter encrypted base64 data</div>';
        return;
    }
    
    try {
        resultEl.innerHTML += '<div style="color: #00b0ff; margin-top: 15px;">🔄 Decrypting image...</div>';
        
        const response = await fetch('/decrypt-image', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ encrypted_base64: encFileBase64 })
        });
        
        const result = await response.json();
        
        if (result.success) {
            decryptedImageData = result.decrypted_base64;
            
            resultEl.innerHTML += `
                <div style="color: #00e676; margin-top: 15px;">🔓 Image Decrypted Successfully</div>
                <div style="color: #bbb; margin-top: 10px;">
                    <strong>Decrypted Size:</strong> ${Math.round(decryptedImageData.length * 0.75 / 1024)} KB<br>
                    <strong>Status:</strong> Ready for download
                </div>
            `;
        } else {
            resultEl.innerHTML += `<div style="color: #ff1744; margin-top: 15px;">❌ Image decryption failed: ${result.message || 'Invalid data'}</div>`;
        }
    } catch (error) {
        resultEl.innerHTML += '<div style="color: #ff1744; margin-top: 15px;">❌ Network error during image decryption</div>';
        console.error('Image decryption error:', error);
    }
}

// Download decrypted image
function downloadDecrypted() {
    if (!decryptedImageData) {
        alert('No decrypted data available. Please decrypt an image first.');
        return;
    }
    
    try {
        const byteCharacters = atob(decryptedImageData);
        const byteNumbers = new Array(byteCharacters.length);
        for (let i = 0; i < byteCharacters.length; i++) {
            byteNumbers[i] = byteCharacters.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteNumbers);
        
        // Try to determine file type from the first few bytes
        let mimeType = 'application/octet-stream';
        let extension = 'bin';
        
        if (byteArray[0] === 0xFF && byteArray[1] === 0xD8) {
            mimeType = 'image/jpeg';
            extension = 'jpg';
        } else if (byteArray[0] === 0x89 && byteArray[1] === 0x50) {
            mimeType = 'image/png';
            extension = 'png';
        } else if (byteArray[0] === 0x47 && byteArray[1] === 0x49) {
            mimeType = 'image/gif';
            extension = 'gif';
        }
        
        const blob = new Blob([byteArray], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `decrypted_image.${extension}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Download error:', error);
        alert('Error downloading decrypted image. Please check the data format.');
    }
}

// Event listeners for Enter key
document.addEventListener('DOMContentLoaded', function() {
    // Login form enter key support
    document.getElementById('username').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') login();
    });
    
    document.getElementById('password').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') login();
    });
    
    // Text encryption enter key support
    document.getElementById('plainText').addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && e.ctrlKey) encryptText();
    });
    
    document.getElementById('cipherInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && e.ctrlKey) decryptText();
    });
    
    document.getElementById('encFileBase64').addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && e.ctrlKey) decryptImage();
    });
    
    // Initialize with login page
    showPage('loginPage');
    showService('text');
});