import React, { useEffect, useState, useCallback } from "react";
import { FaUpload, FaSignOutAlt, FaGoogleDrive, FaDownload, FaTrash, FaSpinner, FaCloudUploadAlt, FaEye } from "react-icons/fa";
import './App.css';


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
  const CLIENT_ID = "1008435627765-144r736ibuofi33smv1o8pj40f38j407.apps.googleusercontent.com";
  const SCOPES = "https://www.googleapis.com/auth/drive.file";

  const [token, setToken] = useState(() => localStorage.getItem('token') || null);
  const [tokenClient, setTokenClient] = useState(null);
  const [isSignedIn, setIsSignedIn] = useState(() => localStorage.getItem('isSignedIn') === 'true');
  const [fileList, setFileList] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState(null);
  const [viewingFile, setViewingFile] = useState(null);

  // Move fetchFileList above useEffect and wrap in useCallback
  const fetchFileList = useCallback(async () => {
    try {
      const res = await fetch(
        "https://www.googleapis.com/drive/v3/files?fields=files(id,name,size,createdTime)",
        {
          headers: new Headers({ Authorization: "Bearer " + token }),
        }
      );
      const data = await res.json();
      console.log("Files:", data.files);
      setFileList(data.files || []);
    } catch (error) {
      console.error("Failed to fetch files:", error);
      setFileList([]);
    }
  }, [token]);

  useEffect(() => {
    if (window.google && !isSignedIn) {
      const signInDiv = document.getElementById("googleSignInDiv");
      if (signInDiv) signInDiv.innerHTML = "";
      window.google.accounts.id.initialize({
        client_id: CLIENT_ID,
        callback: handleCredentialResponse,
      });
      window.google.accounts.id.renderButton(
        document.getElementById("googleSignInDiv"),
        { theme: "outline", size: "large" }
      );
    }
    if (window.google && isSignedIn && !tokenClient) {
      const client = window.google.accounts.oauth2.initTokenClient({
        client_id: CLIENT_ID,
        scope: SCOPES,
        callback: (tokenResponse) => {
          console.log("Access Token:", tokenResponse.access_token);
          setToken(tokenResponse.access_token);
          localStorage.setItem('token', tokenResponse.access_token);
        },
      });
      setTokenClient(client);
    }
  }, [isSignedIn, tokenClient]);

  // Add automatic refresh effect
  useEffect(() => {
    if (token) {
      fetchFileList();
      // Refresh every 2 seconds
      const interval = setInterval(fetchFileList, 2000);
      return () => clearInterval(interval);
    }
  }, [token, fetchFileList]);

  const handleCredentialResponse = (response) => {
    console.log("Signed in! JWT:", response.credential);
    setIsSignedIn(true);
    localStorage.setItem('isSignedIn', 'true');
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
    localStorage.removeItem('token');
    localStorage.removeItem('isSignedIn');
    window.google.accounts.id.disableAutoSelect();
  };

  const handleFileUpload = async (event) => {
    setIsLoading(true);
    setError(null);
    const file = event.target.files[0];
    if (!file) {
      setIsLoading(false);
      return;
    }

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
      fetchFileList();
    } catch (error) {
      console.error("Encryption or upload failed:", error);
      setError("Failed to encrypt or upload the file.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) {
      const event = { target: { files: [file] } };
      handleFileUpload(event);
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

  const handleDeleteFile = async (fileId) => {
    if (!window.confirm("Are you sure you want to delete this file?")) {
      return;
    }

    try {
      const res = await fetch(
        `https://www.googleapis.com/drive/v3/files/${fileId}`,
        {
          method: "DELETE",
          headers: new Headers({ Authorization: "Bearer " + token }),
        }
      );

      if (res.ok) {
        alert("✅ File deleted successfully!");
        // Refresh file list after deletion
        fetchFileList();
      } else {
        throw new Error("Failed to delete file");
      }
    } catch (error) {
      console.error("Delete failed:", error);
      alert("❌ Failed to delete the file.");
    }
  };

  const handleViewFile = async (file) => {
    const password = prompt("🔑 Enter password to view file details:");
    if (!password) return;

    try {
      const encryptedFileNameBase64 = file.name.replace(".enc", "");
      const originalFileName = await decryptText(encryptedFileNameBase64, password);
      
      // Get file type from original filename
      const fileType = originalFileName.split('.').pop().toUpperCase();
      
      setViewingFile({
        name: originalFileName,
        type: fileType,
        size: file.size ? `${(file.size / 1024).toFixed(2)} KB` : "Unknown",
        createdTime: file.createdTime ? new Date(file.createdTime).toLocaleString() : "Unknown"
      });
    } catch (error) {
      console.error("Failed to decrypt filename:", error);
      alert("❌ Failed to view file details. Maybe wrong password?");
    }
  };

  const closeViewModal = () => {
    setViewingFile(null);
  };

  return (
    <div className="container">
      <div className="box auth-box">
        <div className="card-header">
          <span className="card-icon">🔒</span>
          <h1>Encrypted Cloud Storage</h1>
          <p className="tagline">Your files, secured and encrypted in the cloud.</p>
          {isSignedIn && (
            <button className="signout" onClick={handleSignOut}>
              <FaSignOutAlt style={{ fontSize: '1.2em' }} /> Sign Out
            </button>
          )}
        </div>
        {!isSignedIn && (
          <div className="auth-container">
            <p className="auth-message">Sign in to access your encrypted files</p>
            <div id="googleSignInDiv"></div>
          </div>
        )}
        {isSignedIn && !token && (
          <div className="auth-container">
            <div className="status-row">
              <span className="status-badge success">
                <FaGoogleDrive style={{ marginRight: '0.5em' }} /> Signed In
              </span>
              <span className="auth-desc">Authorize Google Drive access to continue</span>
            </div>
            <div className="file-actions">
              <button className="upload big-btn" onClick={handleRequestAccessToken}>
                <FaGoogleDrive style={{ fontSize: '1.5em' }} /> Authorize Google Drive
              </button>
              <button className="signout big-btn" onClick={handleSignOut}>
                <FaSignOutAlt style={{ fontSize: '1.5em' }} /> Sign Out
              </button>
            </div>
          </div>
        )}
        {token && (
          <div className="auth-container">
            <p className="auth-message">
              <span className="status-badge success">Connected</span>
              You are signed in and authorized
            </p>
            <div 
              className={`file-upload-area ${isDragging ? 'dragging' : ''}`}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
            >
              <label className="file-upload-label">
                <FaCloudUploadAlt style={{ fontSize: '2em' }} />
                <span>Drag & Drop or Click to Upload</span>
                <input type="file" onChange={handleFileUpload} />
              </label>
            </div>
          </div>
        )}
      </div>

      {token && (
        <div className="box">
          <div className="file-header">
            <h2>📂 Your Files</h2>
          </div>

          {isLoading && (
            <div className="loading-container">
              <FaSpinner className="spinner" />
              <p>Processing...</p>
            </div>
          )}

          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

          {!isLoading && (!fileList || fileList.length === 0) && (
            <div className="empty-state">
              <p>No files found. Upload your first encrypted file!</p>
            </div>
          )}

          <ul className="file-list">
            {fileList && fileList.map((file) => (
              <li key={file.id} className="file-item">
                <div className="file-info">
                  <span className="file-name" title={file.name}>
                    {file.name}
                  </span>
                  <div className="file-meta">
                    {file.size
                      ? `${(file.size / 1024).toFixed(2)} KB`
                      : "Size: Unknown"}{" "}
                    | {file.createdTime
                      ? new Date(file.createdTime).toLocaleString()
                      : "No date"}
                  </div>
                </div>
                <div className="file-actions">
                  <button
                    className="view"
                    onClick={() => handleViewFile(file)}
                  >
                    <FaEye style={{ fontSize: '1.2em' }} /> View Details
                  </button>
                  <button
                    className="download"
                    onClick={() => handleDownloadAndDecrypt(file)}
                  >
                    <FaDownload style={{ fontSize: '1.2em' }} /> Download & Decrypt
                  </button>
                  <button
                    className="delete"
                    onClick={() => handleDeleteFile(file.id)}
                  >
                    <FaTrash style={{ fontSize: '1.2em' }} /> Delete
                  </button>
                </div>
              </li>
            ))}
          </ul>

          {viewingFile && (
            <div className="modal-overlay" onClick={closeViewModal}>
              <div className="modal-content" onClick={e => e.stopPropagation()}>
                <h3>File Details</h3>
                <div className="file-details">
                  <p><strong>Name:</strong> {viewingFile.name}</p>
                  <p><strong>Type:</strong> {viewingFile.type}</p>
                  <p><strong>Size:</strong> {viewingFile.size}</p>
                  <p><strong>Created:</strong> {viewingFile.createdTime}</p>
                </div>
                <button className="close-modal" onClick={closeViewModal}>Close</button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
