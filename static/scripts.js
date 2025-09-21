function showPage(id) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("visible"));
  document.getElementById(id).classList.add("visible");
}

async function login() {
  const res = await fetch("/login", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({
      username: document.getElementById("username").value,
      password: document.getElementById("password").value
    })
  });
  const data = await res.json();
  if (data.success) showPage("eccPage");
  else document.getElementById("loginMsg").innerText = data.message;
}

async function generateKeys() {
  document.getElementById("loadingAnim").classList.remove("hidden");
  const data = await (await fetch("/generate-keys",{method:"POST"})).json();
  document.getElementById("loadingAnim").classList.add("hidden");
  document.getElementById("eccStatus").innerText = JSON.stringify(data,null,2);
}

async function establishSecret() {
  document.getElementById("loadingAnim").classList.remove("hidden");
  const data = await (await fetch("/establish-secret",{method:"POST"})).json();
  document.getElementById("loadingAnim").classList.add("hidden");
  document.getElementById("eccStatus").innerText = JSON.stringify(data,null,2);
  if (data.success) showPage("servicePage");
}

function showService(type) {
  document.getElementById("textService").classList.add("hidden");
  document.getElementById("imageService").classList.add("hidden");
  document.getElementById("tabText").classList.remove("active");
  document.getElementById("tabImage").classList.remove("active");
  if (type === "text") {
    document.getElementById("textService").classList.remove("hidden");
    document.getElementById("tabText").classList.add("active");
  } else {
    document.getElementById("imageService").classList.remove("hidden");
    document.getElementById("tabImage").classList.add("active");
  }
}

async function encryptText() {
  const data = await (await fetch("/encrypt-text", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({message: document.getElementById("plainText").value})
  })).json();
  document.getElementById("encryptedText").innerText = JSON.stringify(data,null,2);
}

async function decryptText() {
  const data = await (await fetch("/decrypt-text", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({encrypted_hex: document.getElementById("cipherInput").value})
  })).json();
  document.getElementById("decryptedText").innerText = JSON.stringify(data,null,2);
}

let lastEnc="", lastDec="";

async function encryptImage() {
  const file = document.getElementById("imageFile").files[0];
  const formData = new FormData(); formData.append("file", file);
  const data = await (await fetch("/encrypt-image",{method:"POST",body:formData})).json();
  document.getElementById("imageEncryptLog").innerText = JSON.stringify(data,null,2);
  if (data.success) lastEnc=data.encrypted_base64;
}

function copyEncBase64() {
  if (!lastEnc) return alert("No encrypted data yet!");
  navigator.clipboard.writeText(lastEnc); alert("Copied encrypted base64!");
}
function downloadEncFile() {
  if (!lastEnc) return alert("No encrypted data yet!");
  downloadFile(lastEnc,"encrypted.enc","text/plain");
}

async function decryptImage() {
  const b64 = document.getElementById("encFileBase64").value || lastEnc;
  if (!b64) return alert("Provide encrypted base64!");
  const data = await (await fetch("/decrypt-image",{
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({encrypted_base64:b64})
  })).json();
  document.getElementById("imageEncryptLog").innerText = JSON.stringify(data,null,2);
  if (data.success) lastDec=data.decrypted_base64;
}

function downloadDecrypted() {
  if (!lastDec) return alert("No decrypted image yet!");
  const bytes = atob(lastDec).split("").map(c => c.charCodeAt(0));
  downloadFile(new Uint8Array(bytes),"decrypted.png","image/png");
}

function downloadFile(content,name,type) {
  const blob=content instanceof Uint8Array? new Blob([content],{type}) : new Blob([content],{type});
  const a=document.createElement("a"); a.href=URL.createObjectURL(blob);
  a.download=name; a.click();
}

async function logout() {
  await fetch("/logout",{method:"POST"});
  showPage("loginPage");
}
