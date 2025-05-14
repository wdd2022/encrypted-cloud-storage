import React, { useEffect, useState } from "react";
import './App.css';
// 🔐 دالة تشفير النص (اسم الملف)
async function encryptText(text, password) {
  const enc = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"]
  );

  const encryptedContent = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    aesKey,
    enc.encode(text)
  );

  const combinedBuffer = new Uint8Array(
    salt.byteLength + iv.byteLength + encryptedContent.byteLength
  );
  combinedBuffer.set(salt, 0);
  combinedBuffer.set(iv, salt.byteLength);
  combinedBuffer.set(new Uint8Array(encryptedContent), salt.byteLength + iv.byteLength);

  return btoa(String.fromCharCode(...combinedBuffer));
}

// 🔐 دالة تشفير الملف (المحتوى)
async function encryptFileWithPassword(file, password) {
  const enc = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"]
  );

  const fileBuffer = await file.arrayBuffer();

  const encryptedContent = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    aesKey,
    fileBuffer
  );

  const combinedBuffer = new Uint8Array(
    salt.byteLength + iv.byteLength + encryptedContent.byteLength
  );
  combinedBuffer.set(salt, 0);
  combinedBuffer.set(iv, salt.byteLength);
  combinedBuffer.set(new Uint8Array(encryptedContent), salt.byteLength + iv.byteLength);

  return new Blob([combinedBuffer], { type: "application/octet-stream" });
}

// 🔓 دالة فك تشفير النص (اسم الملف)
async function decryptText(encryptedBase64, password) {
  const data = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

  const salt = data.slice(0, 16);
  const iv = data.slice(16, 28);
  const ciphertext = data.slice(28);

  const enc = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["decrypt"]
  );

  const decryptedContent = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    aesKey,
    ciphertext
  );

  return new TextDecoder().decode(decryptedContent);
}

// 🔓 دالة فك تشفير الملف (المحتوى)
async function decryptFile(encryptedBlob, password) {
  const arrayBuffer = await encryptedBlob.arrayBuffer();
  const data = new Uint8Array(arrayBuffer);

  const salt = data.slice(0, 16);
  const iv = data.slice(16, 28);
  const ciphertext = data.slice(28);

  const enc = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["decrypt"]
  );

  const decryptedContent = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    aesKey,
    ciphertext
  );

  return new Blob([decryptedContent]);
}

function App() {
  const CLIENT_ID = "688221994212-9rt2ebg6gpbihvp883u0u2mr1fkhiu9v.apps.googleusercontent.com";
  const SCOPES = "https://www.googleapis.com/auth/drive.file";

  const [token, setToken] = useState(null);
  const [tokenClient, setTokenClient] = useState(null);
  const [isSignedIn, setIsSignedIn] = useState(false);
  const [fileList, setFileList] = useState([]);

  useEffect(() => {
    /* global google */
    if (window.google) {
      window.google.accounts.id.initialize({
        client_id: CLIENT_ID,
        callback: handleCredentialResponse,
      });

      window.google.accounts.id.renderButton(
        document.getElementById("googleSignInDiv"),
        { theme: "outline", size: "large" }
      );

      const client = window.google.accounts.oauth2.initTokenClient({
        client_id: CLIENT_ID,
        scope: SCOPES,
        callback: (tokenResponse) => {
          console.log("Access Token:", tokenResponse.access_token);
          setToken(tokenResponse.access_token);
        },
      });
      setTokenClient(client);
    }
  }, []);

  const handleCredentialResponse = (response) => {
    console.log("Signed in! JWT:", response.credential);
    setIsSignedIn(true);
  };

  const handleRequestAccessToken = () => {
    if (tokenClient) {
      tokenClient.requestAccessToken();
    } else {
      console.error("Token client not ready yet!");
    }
  };

  const handleSignOut = () => {
    setToken(null);
    setIsSignedIn(false);
    window.google.accounts.id.disableAutoSelect();
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    try {
      const password = prompt("🔑 Enter a password for encryption:");
      if (!password) {
        throw new Error("No password provided.");
      }

      const encryptedBlob = await encryptFileWithPassword(file, password);
      const encryptedFileName = await encryptText(file.name, password);

      const metadata = {
        name: encryptedFileName + ".enc",
        mimeType: "application/octet-stream",
      };

      const form = new FormData();
      const blobMetadata = new Blob([JSON.stringify(metadata)], { type: "application/json" });
      form.append("metadata", blobMetadata);
      form.append("file", encryptedBlob);

      const res = await fetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id", {
        method: "POST",
        headers: new Headers({ Authorization: "Bearer " + token }),
        body: form,
      });

      const data = await res.json();
      console.log("Encrypted file uploaded, ID:", data.id);
      alert(`✅ Encrypted file uploaded! ID: ${data.id}`);
    } catch (error) {
      console.error("Encryption or upload failed:", error);
      alert("❌ Failed to encrypt or upload the file.");
    }
  };

  const fetchFileList = async () => {
    try {
      const res = await fetch(
        "https://www.googleapis.com/drive/v3/files?fields=files(id,name,size,createdTime)",
        {
          headers: new Headers({ Authorization: "Bearer " + token }),
        }
      );
      const data = await res.json();
      console.log("Files:", data.files);
      setFileList(data.files);
    } catch (error) {
      console.error("Failed to fetch files:", error);
    }
  };
  

  const handleDownloadAndDecrypt = async (file) => {
    const password = prompt("🔑 Enter password to decrypt:");
    if (!password) return;

    try {
      const res = await fetch(
        `https://www.googleapis.com/drive/v3/files/${file.id}?alt=media`,
        {
          headers: new Headers({ Authorization: "Bearer " + token }),
        }
      );
      const encryptedBlob = await res.blob();

      const decryptedBlob = await decryptFile(encryptedBlob, password);
      const encryptedFileNameBase64 = file.name.replace(".enc", "");
      const originalFileName = await decryptText(encryptedFileNameBase64, password);

      const url = window.URL.createObjectURL(decryptedBlob);
      const a = document.createElement("a");
      a.href = url;
      a.download = originalFileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      alert(`✅ File decrypted and downloaded: ${originalFileName}`);
    } catch (error) {
      console.error("Decryption failed:", error);
      alert("❌ Failed to decrypt the file. Maybe wrong password?");
    }
  };

  return (
    <div  className="container">
    <div className="box">
  <h1>🚀 Encrypted Cloud Storage</h1>

  {!isSignedIn && <div id="googleSignInDiv"></div>}

  {isSignedIn && !token && (
    <>
      <p>✅ Signed in! Now authorize Google Drive access:</p>
      <button className="upload" onClick={handleRequestAccessToken}>Authorize Google Drive Access</button>
      <button className="signout" onClick={handleSignOut}>Sign Out</button>
    </>
  )}

  {token && (
    <>
      <p>✅ You are signed in and authorized. You can now upload files.</p>
      <input type="file" onChange={handleFileUpload} />
      <br /><br />
      <button className="upload" onClick={fetchFileList}>🔄 Fetch Files from Google Drive</button>
    </>
  )}
</div>

{token && (
  <div className="box">
    <h2>📂 Files:</h2>
    <ul>
  {fileList.map((file) => (
    <li key={file.id}>
      <div style={{ flex: 1 }}>
      <span className="file-name" title={file.name}>{file.name}</span>
        <br />
        <small>
          {file.size
            ? `${(file.size / 1024).toFixed(2)} KB`
            : "Size: Unknown"}{" "}
          | {file.createdTime
            ? new Date(file.createdTime).toLocaleString()
            : "No date"}
        </small>
      </div>
      <button className="download" onClick={() => handleDownloadAndDecrypt(file)}>
        ⬇️ Download & Decrypt
      </button>
    </li>
  ))}
</ul>

    <button className="signout" onClick={handleSignOut}>Sign Out</button>
  </div>
)}

    </div>
  );
}

export default App;
