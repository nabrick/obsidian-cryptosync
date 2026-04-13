const { Plugin, Modal, Setting, Notice, Platform, PluginSettingTab } = require("obsidian");

// Sección: CRYPTO
// Algoritmo: AES-GCM 256 bits
// Derivación: PBKDF2 + SHA-256
// Formato: [ 16 bytes salt | 12 bytes IV | ciphertext ]
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const PBKDF2_ITERATIONS = 250_000;

async function deriveKey(passphrase, salt) {
  const raw = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    raw,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptBuffer(passphrase, plainBuffer) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveKey(passphrase, salt);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plainBuffer
  );

  const result = new Uint8Array(SALT_LENGTH + IV_LENGTH + ciphertext.byteLength);
  result.set(salt, 0);
  result.set(iv, SALT_LENGTH);
  result.set(new Uint8Array(ciphertext), SALT_LENGTH + IV_LENGTH);
  return result.buffer;
}

async function decryptBuffer(passphrase, encryptedBuffer) {
  const data = new Uint8Array(encryptedBuffer);
  const salt = data.slice(0, SALT_LENGTH);
  const iv = data.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const ciphertext = data.slice(SALT_LENGTH + IV_LENGTH);
  const key = await deriveKey(passphrase, salt);

  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
}

async function verifyPassphrase(passphrase, encryptedBuffer) {
  try {
    await decryptBuffer(passphrase, encryptedBuffer);
    return true;
  } catch {
    return false;
  }
}

// Sección: Credenciales cifradas
// Cifra solo los campos sensibles de Azure con la passphrase del vault.
// El resto de data.json (checksums, lastBackup, etc.) permanece en claro.
async function encryptCredentials(passphrase, creds) {
  const plain = new TextEncoder().encode(JSON.stringify(creds));
  const buf = await encryptBuffer(passphrase, plain);
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

async function decryptCredentials(passphrase, b64) {
  const binary = atob(b64);
  const buf = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  const plain = await decryptBuffer(passphrase, buf.buffer);
  return JSON.parse(new TextDecoder().decode(plain));
}

// Sección: Storage Providers
// Interface: uploadFile | downloadFile | listFiles | deleteFile
class AzureProvider {
  constructor(storageAccount, container, sasToken) {
    this.base = `https://${storageAccount}.blob.core.windows.net/${container}`;
    this.sas = sasToken.startsWith("?") ? sasToken : `?${sasToken}`;
  }

  async uploadFile(hashedPath, buffer) {
    const url = `${this.base}/${hashedPath}${this.sas}`;
    const res = await fetch(url, {
      method: "PUT",
      headers: {
        "x-ms-blob-type": "BlockBlob",
        "Content-Type":   "application/octet-stream",
        "Content-Length": buffer.byteLength.toString(),
      },
      body: buffer,
    });
    if (!res.ok) throw new Error(`Azure upload error: ${res.status} ${await res.text()}`);
  }

  async downloadFile(hashedPath) {
    const url = `${this.base}/${hashedPath}${this.sas}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Azure download error: ${res.status}`);
    return res.arrayBuffer();
  }

  async listFiles(prefix = "") {
    let url = `${this.base}${this.sas}&restype=container&comp=list`;
    if (prefix) url += `&prefix=${encodeURIComponent(prefix)}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Azure list error: ${res.status}`);
    const text = await res.text();

    const doc   = new DOMParser().parseFromString(text, "text/xml");
    const nodes = doc.querySelectorAll("Name");
    const names = [];
    nodes.forEach(n => names.push(n.textContent));
    return names;
  }

  async getFileMetadata(hashedPath) {
    const url = `${this.base}/${hashedPath}${this.sas}`;
    const res = await fetch(url, { method: "HEAD" });
    if (!res.ok) return null;
    const lastModified = res.headers.get("Last-Modified");
    return lastModified ? new Date(lastModified) : null;
  }

  async deleteFile(hashedPath) {
    const url = `${this.base}/${hashedPath}${this.sas}`;
    const res = await fetch(url, { method: "DELETE" });
    if (!res.ok && res.status !== 404) throw new Error(`Azure delete error: ${res.status}`);
  }
}

// Sección: Plugin
const PLUGIN_DIR = ".obsidian/plugins/cryptosync";
const CRYPTOSYNC_DIR = ".cryptosync";
const CANARY_PATH = `${CRYPTOSYNC_DIR}/vaultsync.enc`;
const MAP_LOCAL = `${CRYPTOSYNC_DIR}/vaultsync-map.enc`;
const MAP_AZURE_KEY = "cryptosync-map.enc";
const CANARY_TEXT = "vaultsync-ok";

const ENCRYPT_EXTENSIONS = [".md", ".png", ".pdf", ".jpeg", ".jpg", ".mp4"];

// Sección: Checksums
const CHECKSUMS_AZURE_KEY = "cryptosync-checksums.enc";
const CHECKSUMS_AZURE_KEY_OLD = "cryptosync-checksums.json";

async function hashContent(buffer) {
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function listAllFiles(adapter, dir = "") {
  try {
    const result = await adapter.list(dir);
    let files = [...result.files];
    for (const folder of result.folders) {
      const children = await listAllFiles(adapter, folder);
      files = files.concat(children);
    }
    return files;
  } catch (e) {
    console.error(`CryptoSync: error listando ${dir}`, e);
    return [];
  }
}

function shouldEncrypt(path) {
  if (path.startsWith(".obsidian/"))  return false;
  if (path.startsWith(".cryptosync/")) return false;
  const ext = "." + path.split(".").pop().toLowerCase();
  return ENCRYPT_EXTENSIONS.includes(ext);
}

async function hashSegment(segment) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(segment));
  const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  return hex.slice(0, 16);
}

async function hashPath(originalPath) {
  const segments = originalPath.split("/");
  const hashed = await Promise.all(segments.map(hashSegment));
  return hashed.join("/") + ".enc";
}

class VaultSyncPlugin extends Plugin {
  passphrase = null;
  storage = null;

  async loadConfig() {
    try {
      const config = await this.loadData() || {};

      let storageAccount, container, sasToken;

      if (config.encryptedCredentials) {
        if (!this.passphrase) {
          console.log("CryptoSync: credenciales cifradas — esperando passphrase");
          return false;
        }
        try {
          const creds    = await decryptCredentials(this.passphrase, config.encryptedCredentials);
          storageAccount = creds.storageAccount;
          container      = creds.container;
          sasToken       = creds.sasToken;
        } catch (e) {
          console.error("CryptoSync: error descifrando credenciales", e);
          return false;
        }
      } else if (config.storageAccount) {
        storageAccount = config.storageAccount;
        container      = config.container;
        sasToken       = config.sasToken;
        if (this.passphrase) {
          console.log("CryptoSync: migrando credenciales a formato cifrado...");
          await this.saveCredentials({ storageAccount, container, sasToken });
          console.log("CryptoSync: migración de credenciales completada ✓");
        }
      } else {
        console.log("CryptoSync: config vacío, Azure desactivado");
        return false;
      }

      if (!storageAccount || !container || !sasToken) return false;

      this.cachedCreds    = { storageAccount, container, sasToken };
      this.cachedSasToken = sasToken;
      this.storage        = new AzureProvider(storageAccount, container, sasToken);
      this.localChecksums = config.localChecksums || {};
      console.log("CryptoSync: Azure configurado");
      return true;
    } catch (e) {
      console.error("CryptoSync: error leyendo config", e);
      return false;
    }
  }

  async saveCredentials(creds) {
    if (!this.passphrase) throw new Error("Vault bloqueado — ingresa tu passphrase primero");
    const config = await this.loadData() || {};
    config.encryptedCredentials = await encryptCredentials(this.passphrase, creds);

    delete config.storageAccount;
    delete config.container;
    delete config.sasToken;
    await this.saveData(config);

    this.cachedCreds    = creds;
    this.cachedSasToken = creds.sasToken;
  }

  // Checksums
  async saveLocalChecksums() {
    try {
      const config = await this.loadData() || {};
      config.localChecksums = this.localChecksums;
      await this.saveData(config);
    } catch (e) {
      console.error("CryptoSync: error guardando localChecksums", e);
    }
  }

  async loadRemoteChecksums() {
    if (!this.passphrase) { this.remoteChecksums = {}; return; }
    try {
      const buf = await this.storage.downloadFile(CHECKSUMS_AZURE_KEY);
      const plain = await decryptBuffer(this.passphrase, buf);
      this.remoteChecksums = JSON.parse(new TextDecoder().decode(plain));
    } catch {
      try {
        const buf  = await this.storage.downloadFile(CHECKSUMS_AZURE_KEY_OLD);
        const text = new TextDecoder().decode(buf);
        this.remoteChecksums = JSON.parse(text);
        console.log("CryptoSync: migrando checksums a formato cifrado...");
        await this.saveRemoteChecksums();
        await this.storage.deleteFile(CHECKSUMS_AZURE_KEY_OLD).catch(() => {});
        console.log("CryptoSync: migración de checksums completada ✓");
      } catch {
        this.remoteChecksums = {};
      }
    }
  }

  async saveRemoteChecksums() {
    if (!this.passphrase) return;
    try {
      const text = JSON.stringify(this.remoteChecksums);
      const plain = new TextEncoder().encode(text);
      const encrypted = await encryptBuffer(this.passphrase, plain);
      await this.storage.uploadFile(CHECKSUMS_AZURE_KEY, encrypted);
    } catch (e) {
      console.error("CryptoSync: error guardando checksums en Azure", e);
    }
  }

  async onload() {
    console.log("CryptoSync: cargando...");

    this.registerEvent(
      this.app.vault.on("modify", (file) => this.onFileModified(file))
    );

    this._beforeUnloadHandler = (e) => {
      if (!this.passphrase) return;
      new Notice("⚠️ Vault sin cifrar — usa 🔒 la próxima vez", 3000);
    };
    window.addEventListener("beforeunload", this._beforeUnloadHandler);

    this.addSettingTab(new CryptoSyncSettingTab(this.app, this));

    this.addRibbonIcon("lock", "Bloquear y cerrar vault", async () => {
      if (!this.passphrase) {
        new Notice("CryptoSync: vault ya está bloqueado");
        return;
      }
      await this.showLockAndCloseModal();
    });

    this.app.workspace.onLayoutReady(async () => {
      const { isFirstTime } = await this.askPassphrase();
      await this.loadConfig();

      if (isFirstTime) {
        await this.showProgressModal("Configurando vault por primera vez...", async () => {
          await this.encryptVault();
          await this.decryptVaultLocal();
        });
      } else {
        await this.showProgressModal("Descifrando vault...", async () => {
          await this.decryptVault();
        });
      }

      new Notice("CryptoSync: listo ✓");
      this.checkTokenExpiry();
    });
  }

  async onunload() {
    if (this._retryTimer) {
      clearTimeout(this._retryTimer);
      this._retryTimer = null;
    }
    this.clearPassphrase();
    window.removeEventListener("beforeunload", this._beforeUnloadHandler);
    console.log("CryptoSync: descargado");
  }

  async canaryExists() {
    return await this.app.vault.adapter.exists(CANARY_PATH);
  }

  async createCanary(passphrase) {
    await this.app.vault.adapter.mkdir(CRYPTOSYNC_DIR);
    const plain = new TextEncoder().encode(CANARY_TEXT);
    const encrypted = await encryptBuffer(passphrase, plain);
    await this.app.vault.adapter.writeBinary(CANARY_PATH, encrypted);
    console.log("CryptoSync: canary creado");
  }

  async checkCanary(passphrase) {
    try {
      const encrypted = await this.app.vault.adapter.readBinary(CANARY_PATH);
      const plain = await decryptBuffer(passphrase, encrypted);
      const text = new TextDecoder().decode(plain);
      return text === CANARY_TEXT;
    } catch {
      return false;
    }
  }

  async askPassphrase() {
    const isFirstTime = !(await this.canaryExists());

    return new Promise((resolve) => {
      new PassphraseModal(this.app, isFirstTime, async (passphrase) => {

        if (isFirstTime) {
          this.passphrase = passphrase;
          await this.createCanary(passphrase);
          resolve({ isFirstTime: true });
        } else {
          const ok = await this.checkCanary(passphrase);
          if (ok) {
            this.passphrase = passphrase;
            resolve({ isFirstTime: false });
          } else {
            new Notice("Passphrase incorrecta, intenta de nuevo");
            await this.askPassphrase().then(resolve);
          }
        }

      }, null).open();
    });
  }

  clearPassphrase() {
    this.passphrase = null;
    this.pathMap    = {};
  }

  checkTokenExpiry() {
    const sasToken = this.cachedSasToken;
    if (!sasToken) return;
    const match = sasToken.match(/se=([^&]+)/);
    if (!match) return;

    const expiry = new Date(decodeURIComponent(match[1]));
    const days   = Math.ceil((expiry - new Date()) / (1000 * 60 * 60 * 24));

    if (days <= 0) {
      new Notice("🔴 CryptoSync: tu SAS token ha vencido — renuévalo en Azure Portal", 10000);
    } else if (days <= 3) {
      new Notice(`🔴 CryptoSync: token vence en ${days} días — ¡renueva ahora!`, 10000);
    } else if (days <= 5) {
      new Notice(`🟠 CryptoSync: token vence en ${days} días — renueva pronto`, 8000);
    } else if (days <= 10) {
      new Notice(`🟡 CryptoSync: token vence en ${days} días`, 5000);
    }
  }

  pathMap = {};
  dirtyFiles = new Set();
  localChecksums = {};
  remoteChecksums = {};
  cachedCreds = null;
  cachedSasToken  = null;

  async saveMap() {
    await this.app.vault.adapter.mkdir(CRYPTOSYNC_DIR);
    const json = JSON.stringify(this.pathMap);
    const plain = new TextEncoder().encode(json);
    const encrypted = await encryptBuffer(this.passphrase, plain);
    await this.app.vault.adapter.writeBinary(MAP_LOCAL, encrypted);
  }

  async loadMap() {
    const exists = await this.app.vault.adapter.exists(MAP_LOCAL);
    if (!exists) { this.pathMap = {}; return; }
    try {
      const encrypted = await this.app.vault.adapter.readBinary(MAP_LOCAL);
      const plain = await decryptBuffer(this.passphrase, encrypted);
      this.pathMap = JSON.parse(new TextDecoder().decode(plain));
    } catch (e) {
      console.error("CryptoSync: error cargando mapa", e);
      this.pathMap = {};
    }
  }

  // Eventos
  debounceTimers = {};

  onFileModified(file) {
    if (!this.passphrase) return;

    clearTimeout(this.debounceTimers[file.path]);

    this.debounceTimers[file.path] = setTimeout(async () => {
      await this.encryptFile(file);
      delete this.debounceTimers[file.path];
    }, 60_000);
  }

  // Reintenta subir archivos pendientes después de un fallo de conexión.
  scheduleRetry() {
    if (this._retryTimer) return;
    this._retryTimer = setTimeout(async () => {
      this._retryTimer = null;
      if (!this.passphrase || !this.storage || this.dirtyFiles.size === 0) return;
      console.log(`CryptoSync: reintentando subida de ${this.dirtyFiles.size} archivo(s) pendiente(s)...`);
      try {
        await this.uploadDirtyFiles();
      } catch {
        console.warn("CryptoSync: retry fallido, se reintentará en la próxima edición");
      }
    }, 30_000);
  }

  async showLockAndCloseModal() {
    const modal = new LockAndCloseModal(this.app, async () => {
      // Cancelar debounce pendientes antes de cifrar
      for (const key of Object.keys(this.debounceTimers)) {
        clearTimeout(this.debounceTimers[key]);
        delete this.debounceTimers[key];
      }
      await this.encryptVault();
      this.clearPassphrase();
    });
    modal.open();
  }

  showProgressModal(message, operation) {
    return new Promise(async (resolve) => {
      const modal = new ProgressModal(this.app, message);
      modal.open();
      try {
        await operation();
      } finally {
        modal.close();
        resolve();
      }
    });
  }

  async encryptVault() {
    if (!this.passphrase) return;
    const allFiles = await listAllFiles(this.app.vault.adapter);
    let count      = 0;

    for (const filePath of allFiles) {
      if (!shouldEncrypt(filePath)) continue;
      if (filePath.endsWith(".enc")) continue;

      try {
        const hashedPath = await hashPath(filePath);
        const dir        = hashedPath.split("/").slice(0, -1).join("/");
        if (dir) await this.app.vault.adapter.mkdir(dir);

        const plain = await this.app.vault.adapter.readBinary(filePath);
        const contentHash = await hashContent(plain);
        const encrypted = await encryptBuffer(this.passphrase, plain);

        await this.app.vault.adapter.writeBinary(hashedPath, encrypted);
        await this.app.vault.adapter.remove(filePath);

        this.pathMap[hashedPath] = filePath;
        this.localChecksums[hashedPath]   = contentHash;
        count++;
      } catch (e) {
        console.error(`CryptoSync: error cifrando ${filePath}`, e);
      }
    }

    await this.saveMap();
    await this.saveLocalChecksums();
    await this.removeEmptyFolders();

    for (const hashedPath of Object.keys(this.pathMap)) {
      this.dirtyFiles.add(hashedPath);
    }

    if (this.storage) {
      const uploaded = await this.uploadDirtyFiles();

      // Backup automático cada 7 días
      if (uploaded > 0) {
        const config     = await this.loadData() || {};
        const lastBackup = config.lastBackup ? new Date(config.lastBackup) : null;
        const daysSince  = lastBackup
          ? (Date.now() - lastBackup.getTime()) / (1000 * 60 * 60 * 24)
          : Infinity;
        if (daysSince >= 7) {
          await this.createBackup();
        }
      }
    }

    console.log(`CryptoSync: ${count} archivos cifrados`);
  }

  async uploadDirtyFiles() {
    if (!this.storage || this.dirtyFiles.size === 0) return 0;
    new Notice(`CryptoSync: subiendo ${this.dirtyFiles.size} archivo(s)...`);
    await this.loadRemoteChecksums();
    let uploaded = 0;

    for (const hashedPath of this.dirtyFiles) {
      if (hashedPath.startsWith(".obsidian/"))   continue;
      if (hashedPath.startsWith(".cryptosync/")) continue;
      try {
        const localHash  = this.localChecksums[hashedPath];
        const remoteHash = this.remoteChecksums[hashedPath];

        if (localHash && localHash === remoteHash) {
          console.log(`CryptoSync: sin cambios, saltando → ${hashedPath}`);
          this.dirtyFiles.delete(hashedPath);
          continue;
        }

        const encExists = await this.app.vault.adapter.exists(hashedPath);
        if (!encExists) {
          this.dirtyFiles.delete(hashedPath);
          continue;
        }

        const encBuf = await this.app.vault.adapter.readBinary(hashedPath);
        await this.storage.uploadFile(hashedPath, encBuf);

        if (localHash) this.remoteChecksums[hashedPath] = localHash;

        this.dirtyFiles.delete(hashedPath);
        uploaded++;
      } catch (e) {
        console.error(`CryptoSync: error subiendo ${hashedPath}`, e);
      }
    }

    try {
      const mapExists = await this.app.vault.adapter.exists(MAP_LOCAL);
      if (mapExists) {
        const mapBuf = await this.app.vault.adapter.readBinary(MAP_LOCAL);
        await this.storage.uploadFile(MAP_AZURE_KEY, mapBuf);
      }
    } catch (e) {
      console.error("CryptoSync: error subiendo mapa", e);
    }

    if (uploaded > 0) {
      await this.saveRemoteChecksums();
      await this.saveLocalChecksums();
      await this.removeEmptyFolders();
    }
    new Notice(`CryptoSync: ${uploaded} archivo(s) subidos ✓`);
    return uploaded;
  }

  async removeEmptyFolders() {
    const folders = this.app.vault.getAllFolders();

    const sorted = folders
      .filter(f => f.path !== "/" && f.path !== ""
        && !f.path.startsWith(".obsidian")
        && !f.path.startsWith(".cryptosync"))
      .sort((a, b) => b.path.split("/").length - a.path.split("/").length);

    for (const folder of sorted) {
      try {
        const real = await this.app.vault.adapter.list(folder.path);
        const isEmpty = real.files.length === 0 && real.folders.length === 0;
        if (isEmpty) {
          await this.app.vault.adapter.rmdir(folder.path, false);
          console.log(`CryptoSync: carpeta vacía eliminada → ${folder.path}`);
        }
      } catch (e) {
        console.warn(`CryptoSync: no se pudo eliminar carpeta → ${folder.path}`, e);
      }
    }
  }

  async decryptVaultLocal() {
    if (!this.passphrase) return;
    await this.loadMap();
    let count = 0;

    for (const [hashedPath, originalPath] of Object.entries(this.pathMap)) {
      try {
        const dir = originalPath.split("/").slice(0, -1).join("/");
        if (dir) await this.app.vault.adapter.mkdir(dir);
        const encrypted = await this.app.vault.adapter.readBinary(hashedPath);
        const plain     = await decryptBuffer(this.passphrase, encrypted);
        await this.app.vault.adapter.writeBinary(originalPath, plain);
        await this.app.vault.adapter.remove(hashedPath);
        count++;
      } catch (e) {
        console.error(`CryptoSync: error descifrando ${hashedPath}`, e);
      }
    }

    this.pathMap = {};
    await this.removeEmptyFolders();
    console.log(`CryptoSync: ${count} archivos descifrados (local)`);
  }

  async decryptVault() {
    if (!this.passphrase) return;

    // Cargar el mapa antes del loop de conflictos para que originalPath esté disponible
    await this.loadMap();

    if (this.storage) {
      new Notice("CryptoSync: sincronizando con Azure...");
      try {
        await this.loadRemoteChecksums();

        const remoteFiles = await this.storage.listFiles();
        let conflicts     = 0;

        for (const hashedPath of remoteFiles) {
          if (hashedPath.startsWith("backup/"))       continue;
          if (hashedPath.startsWith(".obsidian/"))    continue;
          if (hashedPath === CANARY_PATH)             continue;
          if (hashedPath === MAP_AZURE_KEY)           continue;
          if (hashedPath === CHECKSUMS_AZURE_KEY)     continue;
          if (hashedPath === CHECKSUMS_AZURE_KEY_OLD) continue;

          const remoteHash   = this.remoteChecksums[hashedPath];
          const localEncExists = await this.app.vault.adapter.exists(hashedPath);

          if (!localEncExists) {
            const buf = await this.storage.downloadFile(hashedPath);
            const dir = hashedPath.split("/").slice(0, -1).join("/");
            if (dir) await this.app.vault.adapter.mkdir(dir);
            await this.app.vault.adapter.writeBinary(hashedPath, buf);
            if (remoteHash) this.localChecksums[hashedPath] = remoteHash;
            continue;
          }

          if (!remoteHash) continue;

          const localHash = this.localChecksums[hashedPath];

          if (remoteHash === localHash) {
            continue;
          }

          const originalPath = this.pathMap[hashedPath];
          let localCurrentHash = null;
          if (originalPath) {
            const plainExists = await this.app.vault.adapter.exists(originalPath);
            if (plainExists) {
              const plainBuf = await this.app.vault.adapter.readBinary(originalPath);
              localCurrentHash = await hashContent(plainBuf);
            }
          }

          const localAlsoChanged = localCurrentHash && localCurrentHash !== localHash;

          if (localAlsoChanged) {
            if (originalPath) {
              const remoteBuf    = await this.storage.downloadFile(hashedPath);
              const remotePlain  = await decryptBuffer(this.passphrase, remoteBuf);
              const ext          = originalPath.includes(".") ? "." + originalPath.split(".").pop() : "";
              const base         = originalPath.slice(0, originalPath.length - ext.length);
              const date         = new Date().toISOString().slice(0, 10);
              const conflictPath = `${base}-conflicto-${date}${ext}`;
              await this.app.vault.adapter.writeBinary(conflictPath, remotePlain);
              conflicts++;
              console.warn(`CryptoSync: conflicto en ${originalPath} → ${conflictPath}`);
            }
          } else {
            const buf = await this.storage.downloadFile(hashedPath);
            await this.app.vault.adapter.writeBinary(hashedPath, buf);
            this.localChecksums[hashedPath] = remoteHash;
          }
        }

        try {
          const mapBuf = await this.storage.downloadFile(MAP_AZURE_KEY);
          await this.app.vault.adapter.writeBinary(MAP_LOCAL, mapBuf);
        } catch (e) {
          console.log("CryptoSync: mapa no existe en Azure aún, usando local");
        }

        await this.saveLocalChecksums();

        if (conflicts > 0) {
          new Notice(`⚠️ CryptoSync: ${conflicts} conflicto(s) detectado(s) — revisa archivos "-conflicto-"`, 8000);
        }

      } catch (e) {
        console.error("CryptoSync: error bajando de Azure", e);
        new Notice("CryptoSync: error de conexión con Azure, usando copia local");
      }

      // Recargar el mapa por si Azure actualizó MAP_LOCAL durante la sincronización
      await this.loadMap();
    }

    let count = 0;

    for (const [hashedPath, originalPath] of Object.entries(this.pathMap)) {
      if (hashedPath === CANARY_PATH) continue;
      if (hashedPath === MAP_AZURE_KEY) continue;

      try {
        const dir = originalPath.split("/").slice(0, -1).join("/");
        if (dir) await this.app.vault.adapter.mkdir(dir);

        const encrypted = await this.app.vault.adapter.readBinary(hashedPath);
        const plain     = await decryptBuffer(this.passphrase, encrypted);
        await this.app.vault.adapter.writeBinary(originalPath, plain);
        await this.app.vault.adapter.remove(hashedPath);
        count++;
      } catch (e) {
        console.error(`CryptoSync: error descifrando ${hashedPath}`, e);
      }
    }

    this.pathMap = {};
    await this.removeEmptyFolders();
    console.log(`CryptoSync: ${count} archivos descifrados`);
  }

  async encryptFile(file) {
    if (!this.passphrase) return;
    if (!this.storage) return;
    if (!shouldEncrypt(file.path)) return;
    if (file.path.endsWith(".enc")) return;

    try {
      const hashedPath  = await hashPath(file.path);
      const plain       = await this.app.vault.adapter.readBinary(file.path);
      const contentHash = await hashContent(plain);

      if (this.localChecksums[hashedPath] === contentHash) {
        console.log(`CryptoSync: sin cambios, saltando → ${hashedPath}`);
        return;
      }

      if (!this.remoteChecksums[hashedPath]) {
        await this.loadRemoteChecksums();
      }
      if (this.remoteChecksums[hashedPath] === contentHash) {
        console.log(`CryptoSync: remoto ya actualizado, saltando → ${hashedPath}`);
        this.localChecksums[hashedPath] = contentHash;
        await this.saveLocalChecksums();
        return;
      }

      const encBuffer = await encryptBuffer(this.passphrase, plain);
      await this.storage.uploadFile(hashedPath, encBuffer);

      this.pathMap[hashedPath] = file.path;
      await this.saveMap();

      this.localChecksums[hashedPath]  = contentHash;
      this.remoteChecksums[hashedPath] = contentHash;
      await this.saveRemoteChecksums();
      await this.saveLocalChecksums();

      new Notice("↑ Sincronizado con Azure", 3000);
      console.log(`CryptoSync: sincronizado → ${hashedPath}`);
    } catch (e) {
      console.warn(`CryptoSync: error en debounce, reintentando en 30s → ${file.path}`);
      this.dirtyFiles.add(await hashPath(file.path));
      this.scheduleRetry();
    }
  }

  // Rotación de passphrase
  async rotatePassphrase(oldPassphrase, newPassphrase) {
    if (!this.passphrase) throw new Error("Vault bloqueado");
    if (oldPassphrase !== this.passphrase) throw new Error("Passphrase actual incorrecta");
    if (!newPassphrase) throw new Error("La nueva passphrase no puede estar vacía");
    if (newPassphrase === oldPassphrase) throw new Error("La nueva passphrase debe ser diferente a la actual");

    this.passphrase = newPassphrase;

    if (this.cachedCreds) {
      await this.saveCredentials(this.cachedCreds);
    }

    const plain     = new TextEncoder().encode(CANARY_TEXT);
    const encrypted = await encryptBuffer(this.passphrase, plain);
    await this.app.vault.adapter.writeBinary(CANARY_PATH, encrypted);

    await this.encryptVault();
    await this.decryptVaultLocal();

    console.log("CryptoSync: passphrase rotada ✓");
  }

  // Backup
  async createBackup() {
    if (!this.storage) return;
    const date = new Date().toISOString().slice(0, 10);

    new Notice("CryptoSync: creando backup en Azure...");

    const azureFiles = await this.storage.listFiles();
    const toBackup   = azureFiles.filter(f =>
      !f.startsWith("backup/") &&
      f !== MAP_AZURE_KEY
    );

    let count = 0;
    for (const azurePath of toBackup) {
      try {
        const buf = await this.storage.downloadFile(azurePath);
        await this.storage.uploadFile(`backup/${date}/${azurePath}`, buf);
        count++;
      } catch (e) {
        console.error(`CryptoSync: error copiando ${azurePath} al backup`, e);
      }
    }

    try {
      const mapBuf = await this.storage.downloadFile(MAP_AZURE_KEY);
      await this.storage.uploadFile(`backup/${date}/cryptosync-map.enc`, mapBuf);
    } catch (e) {
      console.error("CryptoSync: error copiando mapa al backup", e);
    }

    const config = await this.loadData() || {};
    config.lastBackup = date;
    await this.saveData(config);

    await this.pruneOldBackups(date);

    new Notice(`CryptoSync: backup creado en Azure (${date}) ✓`);
    console.log(`CryptoSync: backup Azure→Azure → backup/${date}/ (${count} archivos)`);
  }

  async pruneOldBackups(keepDate) {
    if (!this.storage) return;
    try {
      const allFiles = await this.storage.listFiles("backup/");
      const toDelete = allFiles.filter(f => !f.startsWith(`backup/${keepDate}/`));
      for (const f of toDelete) {
        await this.storage.deleteFile(f).catch(() => {});
      }
      if (toDelete.length > 0) {
        console.log(`CryptoSync: ${toDelete.length} archivo(s) de backup antiguo eliminados`);
      }
    } catch (e) {
      console.error("CryptoSync: error limpiando backups viejos", e);
    }
  }

  async restoreFromBackup(date) {
    if (!this.passphrase) {
      new Notice("CryptoSync: debes tener el vault desbloqueado para restaurar");
      return;
    }
    if (!this.storage) {
      new Notice("CryptoSync: Azure no configurado");
      return;
    }

    await this.showProgressModal(`Restaurando backup del ${date}...`, async () => {
      const backupFiles = await this.storage.listFiles(`backup/${date}/`);

      if (backupFiles.length === 0) {
        throw new Error(`No se encontraron archivos en el backup del ${date}`);
      }

      const prefix = `backup/${date}/`;
      let copied   = 0;

      for (const backupPath of backupFiles) {
        const rootPath = backupPath.slice(prefix.length);
        if (!rootPath) continue;
        if (!rootPath.endsWith(".enc")) continue;
        try {
          const buf = await this.storage.downloadFile(backupPath);
          await this.storage.uploadFile(rootPath, buf);
          copied++;
        } catch (e) {
          console.error(`CryptoSync: error copiando ${backupPath} → ${rootPath}`, e);
        }
      }

      console.log(`CryptoSync: ${copied} archivos copiados de backup/${date}/ al root de Azure`);

      await this.decryptVault();
    });

    new Notice("CryptoSync: vault restaurado desde backup ✓");
  }
}

// Modal: Pedir passphrase
class PassphraseModal extends Modal {
  constructor(app, isFirstTime, onSubmit, onDismiss) {
    super(app);
    this.isFirstTime = isFirstTime;
    this.onSubmit = onSubmit;
    this.onDismiss = onDismiss;
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "CryptoSync", cls: "cryptosync-title" });
    contentEl.createEl("p", {
      text: this.isFirstTime
        ? "Primera vez: define tu passphrase"
        : "Ingresa tu passphrase para descifrar el vault",
      cls: "cryptosync-subtitle"
    });

    let passphrase = "";

    new Setting(contentEl)
      .setName("Passphrase")
      .addText((text) => {
        text.inputEl.type = "password";
        text.setPlaceholder(
          this.isFirstTime ? "Elige una passphrase segura..." : "Tu passphrase..."
        );
        text.onChange((val) => (passphrase = val));
        text.inputEl.addEventListener("keydown", (e) => {
          if (e.key === "Enter") this.submit(passphrase);
        });
        setTimeout(() => text.inputEl.focus(), 50);
      });

    new Setting(contentEl).addButton((btn) =>
      btn
        .setButtonText(this.isFirstTime ? "Crear vault" : "Entrar")
        .setCta()
        .onClick(() => this.submit(passphrase))
    );
  }

  submit(passphrase) {
    if (!passphrase) {
      new Notice("Ingresa una passphrase");
      return;
    }
    this.submitted = true;
    this.close();
    this.onSubmit(passphrase);
  }

  onClose() {
    this.contentEl.empty();
  }
}

// Modal: Cierre con confirmación
class LockAndCloseModal extends Modal {
  constructor(app, onEncryptDone) {
    super(app);
    this.onEncryptDone = onEncryptDone;
    this.containerEl.addEventListener("click", (e) => e.stopPropagation());
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "CryptoSync", cls: "cryptosync-title" });

    const wrap     = contentEl.createDiv({ cls: "cryptosync-progress" });
    this.statusEl  = wrap.createEl("p", { text: "⏳ Cifrando vault...", cls: "cryptosync-status" });
    this.spinnerEl = wrap.createDiv({ cls: "cryptosync-spinner" });
    this.spinnerEl.setText("⏳");
    this.hintEl    = wrap.createEl("p", { text: "No cierres ni muevas archivos..." });
    this.btnEl     = contentEl.createDiv();

    this.onEncryptDone().then(() => {
      this.statusEl.setText("🔒 Vault cifrado");
      this.statusEl.addClass("success");
      this.spinnerEl.empty();
      this.hintEl.setText("Ya puedes cerrar Obsidian.");

      const btn = this.btnEl.createEl("button", { text: "OK", cls: "cryptosync-btn-full" });
      btn.addEventListener("click", () => this.close());
    }).catch((e) => {
      this.statusEl.setText("Error al cifrar, revisa la consola (F12)");
      this.statusEl.addClass("error");
      this.spinnerEl.empty();
      this.hintEl.empty();
      console.error("CryptoSync: error en cierre", e);
    });
  }

  onClose() {
    this.contentEl.empty();
  }
}

// Modal: Progreso para bloquear UI durante cifrado/descifrado
class ProgressModal extends Modal {
  constructor(app, message) {
    super(app);
    this.message = message;
    this.modalEl.addEventListener("keydown", (e) => e.stopPropagation());
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "CryptoSync" });

    const wrap = contentEl.createDiv({ cls: "cryptosync-progress" });
    wrap.createEl("p", { text: this.message, cls: "cryptosync-status" });
    wrap.createDiv({ cls: "cryptosync-spinner" }).setText("⏳");
    wrap.createEl("p", { text: "No cierres ni muevas archivos..." });
  }

  onClose() {
    this.contentEl.empty();
  }
}

// Modal: Confirmación para acciones destructivas
class ConfirmModal extends Modal {
  constructor(app, message, onConfirm) {
    super(app);
    this.message   = message;
    this.onConfirm = onConfirm;
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "⚠️ Confirmar", cls: "cryptosync-title" });
    contentEl.createEl("p",  { text: this.message, cls: "cryptosync-confirm-message" });

    new Setting(contentEl)
      .addButton(btn => btn
        .setButtonText("Cancelar")
        .onClick(() => this.close())
      )
      .addButton(btn => btn
        .setButtonText("Confirmar")
        .setWarning()
        .onClick(() => {
          this.close();
          this.onConfirm();
        })
      );
  }

  onClose() {
    this.contentEl.empty();
  }
}

class CryptoSyncSettingTab extends PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  parseSasExpiry(sasToken) {
    try {
      const match = sasToken.match(/se=([^&]+)/);
      if (!match) return null;
      return new Date(decodeURIComponent(match[1]));
    } catch {
      return null;
    }
  }

  daysUntilExpiry(expiryDate) {
    if (!expiryDate) return null;
    const diff = expiryDate - new Date();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  }

  expiryStatus(days) {
    if (days === null) return { icon: "🔴", text: "No se pudo leer la fecha" };
    if (days <= 0)     return { icon: "🔴", text: "Token vencido" };
    if (days <= 3)     return { icon: "🔴", text: `Vence en ${days} días — ¡renueva ahora!` };
    if (days <= 5)     return { icon: "🟠", text: `Vence en ${days} días — renueva pronto` };
    if (days <= 10)    return { icon: "🟡", text: `Vence en ${days} días` };
    return { icon: "🟢", text: `Vence el ${this.parseSasExpiry(this._currentToken)?.toLocaleDateString()}` };
  }

  async display() {
    const { containerEl } = this;
    containerEl.empty();

    let config = {
      storageAccount: this.plugin.cachedCreds?.storageAccount || "",
      container:      this.plugin.cachedCreds?.container      || "",
      sasToken:       this.plugin.cachedCreds?.sasToken        || ""
    };
    this._currentToken = config.sasToken;
    let showToken = false;

    const header = containerEl.createDiv({ cls: "cryptosync-settings-header" });
    header.createEl("span", { text: "🔒", cls: "cryptosync-settings-icon" });
    const headerText = header.createDiv();
    headerText.createEl("div", { text: "CryptoSync", cls: "cryptosync-settings-title" });
    headerText.createEl("div", {
      text: "Cifrado AES-GCM 256 · Azure Blob Storage",
      cls: "cryptosync-settings-subtitle"
    });

    // Sección: Conexión Azure
    containerEl.createEl("h3", { text: "Conexión Azure", cls: "cryptosync-section-heading" });
    const azureCard = containerEl.createDiv({ cls: "cryptosync-card" });

    new Setting(azureCard)
      .setName("Storage Account")
      .setDesc("Nombre de tu cuenta de Azure Blob Storage")
      .addText(text => text
        .setPlaceholder("miCuenta")
        .setValue(config.storageAccount)
        .onChange(val => { config.storageAccount = val; })
      );

    new Setting(azureCard)
      .setName("Container")
      .setDesc("Nombre del contenedor donde se guardan los archivos cifrados")
      .addText(text => text
        .setPlaceholder("mi-vault")
        .setValue(config.container)
        .onChange(val => { config.container = val; })
      );

    let tokenInput;
    new Setting(azureCard)
      .setName("SAS Token")
      .setDesc("Token de acceso compartido (se cifra con tu passphrase, nunca se guarda en claro)")
      .addText(text => {
        tokenInput = text;
        text.inputEl.type = "password";
        text.inputEl.style.width = "100%";
        text.setPlaceholder("sv=2022-11-02&ss=b&...")
            .setValue(config.sasToken)
            .onChange(val => {
              config.sasToken    = val;
              this._currentToken = val;
              updateExpiryInfo(val);
            });
      })
      .addExtraButton(btn => btn
        .setIcon("eye")
        .setTooltip("Mostrar/ocultar token")
        .onClick(() => {
          showToken = !showToken;
          tokenInput.inputEl.type = showToken ? "text" : "password";
        })
      );

    const expiryEl = azureCard.createDiv({ cls: "cryptosync-expiry" });

    const updateExpiryInfo = (token) => {
      const expiry = this.parseSasExpiry(token);
      const days   = this.daysUntilExpiry(expiry);
      const status = this.expiryStatus(days);
      expiryEl.empty();
      const row = expiryEl.createDiv({ cls: "cryptosync-expiry-row" });
      row.createSpan({ text: `${status.icon}` });
      row.createSpan({
        text: ` Token SAS: ${status.text}`,
        cls: days !== null && days <= 5 ? "cryptosync-warning" : "cryptosync-expiry-text"
      });
    };
    updateExpiryInfo(config.sasToken);

    const connStatusEl = azureCard.createDiv({ cls: "cryptosync-conn-status" });

    const actionRow = azureCard.createDiv({ cls: "cryptosync-action-row" });

    const testBtn = actionRow.createEl("button", {
      text: "Probar conexión",
      cls: "cryptosync-btn-secondary"
    });
    testBtn.addEventListener("click", async () => {
      connStatusEl.setText("⏳ Probando conexión...");
      connStatusEl.className = "cryptosync-conn-status";
      try {
        const provider = new AzureProvider(config.storageAccount, config.container, config.sasToken);
        await provider.listFiles();
        connStatusEl.setText("🟢 Conexión exitosa");
        connStatusEl.addClass("cryptosync-status-ok");
      } catch (e) {
        connStatusEl.setText(`🔴 ${e.message}`);
        connStatusEl.addClass("cryptosync-status-error");
      }
    });

    const saveBtn = actionRow.createEl("button", {
      text: "Guardar configuración",
      cls: "cryptosync-btn-primary"
    });
    saveBtn.addEventListener("click", async () => {
      try {
        await this.plugin.saveCredentials({
          storageAccount: config.storageAccount,
          container:      config.container,
          sasToken:       config.sasToken
        });
        await this.plugin.loadConfig();
        saveBtn.setText("✓ Guardado");
        setTimeout(() => saveBtn.setText("Guardar configuración"), 2000);
        new Notice("CryptoSync: configuración guardada ✓");
      } catch (e) {
        new Notice(`CryptoSync: error guardando — ${e.message}`);
      }
    });

    // Sección: Seguridad
    containerEl.createEl("h3", { text: "Seguridad", cls: "cryptosync-section-heading" });
    const secCard = containerEl.createDiv({ cls: "cryptosync-card" });

    new Setting(secCard)
      .setName("Cambiar passphrase")
      .setDesc("Re-cifra todo el vault con una nueva passphrase. El proceso puede tardar según el tamaño del vault.")
      .addButton(btn => btn
        .setButtonText("Cambiar passphrase")
        .setWarning()
        .onClick(() => {
          if (!this.plugin.passphrase) {
            new Notice("CryptoSync: el vault debe estar desbloqueado para cambiar la passphrase");
            return;
          }
          new ChangePassphraseModal(this.app, this.plugin).open();
        })
      );

    // Sección: Backup
    containerEl.createEl("h3", { text: "Backup automático", cls: "cryptosync-section-heading" });
    const backupCard = containerEl.createDiv({ cls: "cryptosync-card" });

    const backupStatusEl = backupCard.createDiv({ cls: "cryptosync-backup-status" });

    const refreshBackupInfo = async () => {
      const cfg        = await this.plugin.loadData() || {};
      const lastBackup = cfg.lastBackup;
      backupStatusEl.empty();

      if (!lastBackup) {
        const icon = backupStatusEl.createDiv({ cls: "cryptosync-backup-icon" });
        icon.setText("📭");
        const info = backupStatusEl.createDiv({ cls: "cryptosync-backup-info" });
        info.createEl("div", { text: "Sin backup todavía", cls: "cryptosync-backup-label" });
        info.createEl("div", {
          text: "El primer backup se creará automáticamente cuando sincronices.",
          cls: "cryptosync-backup-meta"
        });
      } else {
        const days = Math.floor(
          (Date.now() - new Date(lastBackup).getTime()) / (1000 * 60 * 60 * 24)
        );
        const label = days === 0 ? "Hoy" : days === 1 ? "Hace 1 día" : `Hace ${days} días`;
        const nextIn = Math.max(0, 7 - days);
        const nextLabel = nextIn === 0 ? "hoy" : nextIn === 1 ? "mañana" : `en ${nextIn} días`;

        const icon = backupStatusEl.createDiv({ cls: "cryptosync-backup-icon" });
        icon.setText("📦");
        const info = backupStatusEl.createDiv({ cls: "cryptosync-backup-info" });
        info.createEl("div", { text: label, cls: "cryptosync-backup-label" });
        info.createEl("div", { text: lastBackup, cls: "cryptosync-backup-date" });
        info.createEl("div", {
          text: `Próxima actualización automática ${nextLabel}`,
          cls: "cryptosync-backup-meta"
        });
      }
    };

    await refreshBackupInfo();

    backupCard.createEl("p", {
      text: "El backup se guarda íntegramente en Azure. Tus datos nunca salen del cifrado y el snapshot se actualiza solo cada 7 días.",
      cls: "cryptosync-backup-desc"
    });

    new Setting(backupCard)
      .setName("Restaurar desde backup")
      .setDesc("Reemplaza tu vault local con el snapshot guardado en Azure. El backup en la nube no se toca.")
      .addButton(btn => btn
        .setButtonText("Restaurar backup")
        .setWarning()
        .onClick(async () => {
          const cfg        = await this.plugin.loadData() || {};
          const lastBackup = cfg.lastBackup;
          if (!lastBackup) {
            new Notice("CryptoSync: no hay backup disponible todavía");
            return;
          }
          new ConfirmModal(this.app,
            `¿Restaurar el vault al estado del ${lastBackup}? Esto reemplazará tu contenido local actual.`,
            async () => {
              try {
                await this.plugin.restoreFromBackup(lastBackup);
                await refreshBackupInfo();
              } catch (e) {
                new Notice(`CryptoSync: error restaurando backup — ${e.message}`);
              }
            }
          ).open();
        })
      );
  }
}

// Modal: Cambiar passphrase
class ChangePassphraseModal extends Modal {
  constructor(app, plugin) {
    super(app);
    this.plugin = plugin;
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "CryptoSync", cls: "cryptosync-title" });
    contentEl.createEl("p", {
      text: "Cambia tu passphrase. Todo el vault será re-cifrado automáticamente.",
      cls: "cryptosync-subtitle"
    });

    let oldPass  = "";
    let newPass  = "";
    let newPass2 = "";

    new Setting(contentEl)
      .setName("Passphrase actual")
      .addText(text => {
        text.inputEl.type = "password";
        text.setPlaceholder("Tu passphrase actual...");
        text.onChange(val => { oldPass = val; });
        setTimeout(() => text.inputEl.focus(), 50);
      });

    new Setting(contentEl)
      .setName("Nueva passphrase")
      .addText(text => {
        text.inputEl.type = "password";
        text.setPlaceholder("Elige una passphrase segura...");
        text.onChange(val => { newPass = val; });
      });

    new Setting(contentEl)
      .setName("Confirmar nueva passphrase")
      .addText(text => {
        text.inputEl.type = "password";
        text.setPlaceholder("Repite la nueva passphrase...");
        text.onChange(val => { newPass2 = val; });
        text.inputEl.addEventListener("keydown", e => {
          if (e.key === "Enter") this.submit(oldPass, newPass, newPass2);
        });
      });

    const statusEl = contentEl.createEl("p", { cls: "cryptosync-conn-status" });

    new Setting(contentEl)
      .addButton(btn => btn
        .setButtonText("Cancelar")
        .onClick(() => this.close())
      )
      .addButton(btn => btn
        .setButtonText("Cambiar passphrase")
        .setCta()
        .onClick(() => this.submit(oldPass, newPass, newPass2, statusEl))
      );
  }

  async submit(oldPass, newPass, newPass2, statusEl) {
    if (!oldPass || !newPass || !newPass2) {
      statusEl.setText("Completa todos los campos");
      statusEl.className = "cryptosync-conn-status cryptosync-status-error";
      return;
    }
    if (newPass !== newPass2) {
      statusEl.setText("Las nuevas passphrase no coinciden");
      statusEl.className = "cryptosync-conn-status cryptosync-status-error";
      return;
    }
    if (newPass === oldPass) {
      statusEl.setText("La nueva passphrase debe ser diferente a la actual");
      statusEl.className = "cryptosync-conn-status cryptosync-status-error";
      return;
    }

    statusEl.setText("⏳ Re-cifrando vault...");
    statusEl.className = "cryptosync-conn-status";

    try {
      await this.plugin.rotatePassphrase(oldPass, newPass);
      this.submitted = true;
      this.close();
      new Notice("CryptoSync: passphrase cambiada ✓", 5000);
    } catch (e) {
      statusEl.setText(`🔴 ${e.message}`);
      statusEl.className = "cryptosync-conn-status cryptosync-status-error";
    }
  }

  onClose() {
    this.contentEl.empty();
  }
}

module.exports = VaultSyncPlugin;