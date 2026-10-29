const DATA_FILE = "shows.enc.json";
const FORMAT = "family-watchlist";
const VERSION = 1;
const PBKDF2_ITERATIONS = 600_000;
const KEY_DB_NAME = "family-watchlist-device-key";
const KEY_STORE_NAME = "keys";

const lockPanel = document.querySelector("#lock-panel");
const watchlistPanel = document.querySelector("#watchlist-panel");
const lockDescription = document.querySelector("#lock-description");
const unlockButton = document.querySelector("#unlock-button");
const passphraseInput = document.querySelector("#passphrase");
const confirmWrap = document.querySelector("#confirm-wrap");
const confirmInput = document.querySelector("#confirm-passphrase");
const rememberDeviceInput = document.querySelector("#remember-device");
const forgetDeviceButton = document.querySelector("#forget-device");
const notice = document.querySelector("#notice");
const showList = document.querySelector("#show-list");
const emptyState = document.querySelector("#empty-state");
const showCount = document.querySelector("#show-count");

let encryptedFile = null;
let createNewList = false;
let currentPassphrase = "";
let currentCryptoKey = null;
let currentSalt = null;
let rememberThisDevice = false;
let shows = [];

function setNotice(message = "", isError = false) {
  notice.textContent = message;
  notice.hidden = !message;
  notice.classList.toggle("is-error", isError);
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  if (busy) {
    button.dataset.originalLabel = button.innerHTML;
    button.textContent = label;
  } else if (button.dataset.originalLabel) {
    button.innerHTML = button.dataset.originalLabel;
    delete button.dataset.originalLabel;
  }
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error("The encrypted file is not in a valid format.");
  }
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function deriveKey(passphrase, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function openKeyDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(KEY_DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(KEY_STORE_NAME);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function getRememberedKey() {
  const database = await openKeyDatabase();
  return new Promise((resolve, reject) => {
    const request = database.transaction(KEY_STORE_NAME, "readonly").objectStore(KEY_STORE_NAME).get("current");
    request.onsuccess = () => {
      database.close();
      resolve(request.result ?? null);
    };
    request.onerror = () => {
      database.close();
      reject(request.error);
    };
  });
}

async function saveRememberedKey(record) {
  const database = await openKeyDatabase();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(KEY_STORE_NAME, "readwrite");
    transaction.objectStore(KEY_STORE_NAME).put(record, "current");
    transaction.oncomplete = () => {
      database.close();
      resolve();
    };
    transaction.onerror = () => {
      database.close();
      reject(transaction.error);
    };
  });
}

async function clearRememberedKey() {
  const database = await openKeyDatabase();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(KEY_STORE_NAME, "readwrite");
    transaction.objectStore(KEY_STORE_NAME).delete("current");
    transaction.oncomplete = () => {
      database.close();
      resolve();
    };
    transaction.onerror = () => {
      database.close();
      reject(transaction.error);
    };
  });
}

async function fileFingerprint(file) {
  const bytes = new TextEncoder().encode(JSON.stringify(file));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToBase64(new Uint8Array(digest));
}

async function rememberCurrentKey(file = encryptedFile) {
  if (!rememberThisDevice || !currentCryptoKey || !file) return;
  await saveRememberedKey({ fingerprint: await fileFingerprint(file), key: currentCryptoKey });
  forgetDeviceButton.hidden = false;
}

function validateShows(value) {
  if (!value || typeof value !== "object" || !Array.isArray(value.shows)) {
    throw new Error("The decrypted watchlist has an unexpected format.");
  }
  if (value.shows.length > 2_000) throw new Error("This watchlist contains too many entries.");
  return value.shows.map((show) => {
    if (!show || typeof show.title !== "string" || typeof show.imdbUrl !== "string") {
      throw new Error("An entry in the watchlist is incomplete.");
    }
    const url = new URL(show.imdbUrl);
    if (url.protocol !== "https:" || !["imdb.com", "www.imdb.com", "m.imdb.com"].includes(url.hostname)) {
      throw new Error("The watchlist contains a link that is not a valid IMDb link.");
    }
    return {
      id: typeof show.id === "string" ? show.id : crypto.randomUUID(),
      title: show.title.slice(0, 120),
      imdbUrl: url.href,
      note: typeof show.note === "string" ? show.note.slice(0, 240) : "",
    };
  });
}

async function decryptWatchlist(file, passphrase) {
  if (!file || file.format !== FORMAT || file.version !== VERSION || file.cipher !== "AES-256-GCM" || file.kdf !== "PBKDF2-SHA-256") {
    throw new Error("This isn't a supported encrypted watchlist file.");
  }
  if (!Number.isInteger(file.iterations) || file.iterations < 100_000 || file.iterations > 1_000_000) {
    throw new Error("The encrypted file has invalid security settings.");
  }
  const salt = base64ToBytes(file.salt);
  const iv = base64ToBytes(file.iv);
  const ciphertext = base64ToBytes(file.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length > 1_000_000) {
    throw new Error("The encrypted file is damaged or too large.");
  }
  const key = await deriveKey(passphrase, salt, file.iterations);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return { shows: validateShows(JSON.parse(new TextDecoder().decode(plaintext))), key, salt };
}

async function decryptWithKey(file, key) {
  if (!file || file.format !== FORMAT || file.version !== VERSION || file.cipher !== "AES-256-GCM" || file.kdf !== "PBKDF2-SHA-256") {
    throw new Error("This isn't a supported encrypted watchlist file.");
  }
  const salt = base64ToBytes(file.salt);
  const iv = base64ToBytes(file.iv);
  const ciphertext = base64ToBytes(file.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length > 1_000_000) {
    throw new Error("The encrypted file is damaged or too large.");
  }
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return { shows: validateShows(JSON.parse(new TextDecoder().decode(plaintext))), key, salt };
}

async function encryptWatchlist(passphrase, reusableKey = null, reusableSalt = null) {
  const salt = reusableSalt ?? crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = reusableKey ?? await deriveKey(passphrase, salt, PBKDF2_ITERATIONS);
  const plaintext = new TextEncoder().encode(JSON.stringify({ shows }));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  const file = {
    format: FORMAT,
    version: VERSION,
    cipher: "AES-256-GCM",
    kdf: "PBKDF2-SHA-256",
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
  return { file, key, salt };
}

function renderShows() {
  showList.replaceChildren();
  showCount.textContent = String(shows.length);
  emptyState.hidden = shows.length > 0;

  for (const show of shows) {
    const item = document.createElement("li");
    item.className = "show-item";

    const icon = document.createElement("span");
    icon.className = "poster-mark";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = "✦";

    const info = document.createElement("div");
    info.className = "show-info";
    const link = document.createElement("a");
    link.className = "show-title";
    link.href = show.imdbUrl;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = show.title;
    info.append(link);
    if (show.note) {
      const note = document.createElement("p");
      note.className = "show-note";
      note.textContent = show.note;
      info.append(note);
    }

    const remove = document.createElement("button");
    remove.className = "remove-button";
    remove.type = "button";
    remove.setAttribute("aria-label", `Remove ${show.title}`);
    remove.title = "Remove from list";
    remove.textContent = "×";
    remove.addEventListener("click", () => {
      shows = shows.filter((entry) => entry.id !== show.id);
      renderShows();
      setNotice("Removed from this browser’s list. Encrypt and download to share the change.");
    });

    item.append(icon, info, remove);
    showList.append(item);
  }
}

function openWatchlist() {
  lockPanel.hidden = true;
  watchlistPanel.hidden = false;
  renderShows();
  setNotice("");
  document.querySelector("#list-heading").focus({ preventScroll: true });
}

async function loadEncryptedFile() {
  try {
    const response = await fetch(new URL(DATA_FILE, window.location.href), { cache: "no-store" });
    if (response.status === 404) {
      createNewList = true;
      lockDescription.textContent = "Create the family list with a strong passphrase. Then encrypt and upload it to GitHub.";
      confirmWrap.hidden = false;
      confirmInput.required = true;
      passphraseInput.autocomplete = "new-password";
      unlockButton.innerHTML = 'Create secure list <span aria-hidden="true">→</span>';
      return;
    }
    if (!response.ok) throw new Error(`Could not load the encrypted list (HTTP ${response.status}).`);
    encryptedFile = await response.json();
    try {
      const saved = await getRememberedKey();
      if (saved) {
        forgetDeviceButton.hidden = false;
        if (saved.fingerprint === await fileFingerprint(encryptedFile)) {
          const result = await decryptWithKey(encryptedFile, saved.key);
          shows = result.shows;
          currentCryptoKey = result.key;
          currentSalt = result.salt;
          rememberThisDevice = true;
          rememberDeviceInput.checked = true;
          openWatchlist();
          setNotice("Unlocked with the key saved in this browser profile.");
        } else {
          await clearRememberedKey();
          forgetDeviceButton.hidden = true;
          setNotice("The shared list has changed since this browser saved its unlock key. Enter the passphrase to continue.");
        }
      }
    } catch {
      try { await clearRememberedKey(); } catch { /* Continue with passphrase unlock if browser storage is unavailable. */ }
      forgetDeviceButton.hidden = true;
      setNotice("The saved device key is unavailable. Enter the family passphrase to unlock the list.");
    }
  } catch (error) {
    if (error instanceof TypeError) {
      setNotice("Could not load the encrypted list. Open this site over HTTPS or use a local web server; opening index.html directly is not supported.", true);
    } else {
      setNotice(error.message || "Could not load the encrypted list.", true);
    }
  }
}

document.querySelector("#unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setNotice("");
  const passphrase = passphraseInput.value;
  if (passphrase.length < 12) {
    setNotice("Use a passphrase with at least 12 characters.", true);
    return;
  }
  if (createNewList && passphrase !== confirmInput.value) {
    setNotice("Those passphrases don’t match.", true);
    return;
  }

  const isCreatingList = createNewList;
  setBusy(unlockButton, true, isCreatingList ? "Creating…" : "Unlocking…");
  let rememberError = false;
  try {
    if (createNewList) {
      shows = [];
      const result = await encryptWatchlist(passphrase);
      encryptedFile = result.file;
      currentCryptoKey = result.key;
      currentSalt = result.salt;
      createNewList = false;
      confirmWrap.hidden = true;
      confirmInput.required = false;
      passphraseInput.autocomplete = "current-password";
      lockDescription.textContent = "Enter the shared passphrase to see the shows and movies we’ve saved.";
      unlockButton.innerHTML = 'Unlock watchlist <span aria-hidden="true">→</span>';
    } else {
      const result = await decryptWatchlist(encryptedFile, passphrase);
      shows = result.shows;
      currentCryptoKey = result.key;
      currentSalt = result.salt;
    }
    currentPassphrase = passphrase;
    rememberThisDevice = rememberDeviceInput.checked;
    if (rememberThisDevice) {
      try {
        await rememberCurrentKey();
      } catch {
        rememberError = true;
      }
    } else {
      try { await clearRememberedKey(); } catch { /* The list can still be unlocked without local persistence. */ }
      forgetDeviceButton.hidden = true;
    }
    openWatchlist();
    if (rememberError) setNotice("The list is unlocked, but this browser could not save the device key. You’ll need the passphrase again after refresh.", true);
    else if (isCreatingList) setNotice("Your list is ready. Add a title, then encrypt and download it to publish the encrypted file.");
  } catch {
    setNotice(createNewList ? "Could not create the watchlist in this browser. Check that you’re using a secure, up-to-date browser." : "Could not unlock the list. Check the passphrase and try again.", true);
  } finally {
    setBusy(unlockButton, false);
    if (!createNewList) unlockButton.innerHTML = 'Unlock watchlist <span aria-hidden="true">→</span>';
  }
});

document.querySelector("#add-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  const title = String(formData.get("title")).trim();
  const imdbUrl = String(formData.get("imdbUrl")).trim();
  const note = String(formData.get("note")).trim();

  let parsedUrl;
  try {
    parsedUrl = new URL(imdbUrl);
  } catch {
    setNotice("Enter a valid IMDb link, such as https://www.imdb.com/title/…", true);
    return;
  }
  if (parsedUrl.protocol !== "https:" || !["imdb.com", "www.imdb.com", "m.imdb.com"].includes(parsedUrl.hostname)) {
    setNotice("Please use a secure link from imdb.com.", true);
    return;
  }
  if (!title) return;

  shows.unshift({ id: crypto.randomUUID(), title, imdbUrl: parsedUrl.href, note });
  form.reset();
  renderShows();
  setNotice("Added to this browser’s list. Encrypt and download to share the change.");
});

document.querySelector("#save-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  setNotice("");
  setBusy(button, true, "Encrypting…");
  try {
    const result = await encryptWatchlist(currentPassphrase, currentPassphrase ? null : currentCryptoKey, currentPassphrase ? null : currentSalt);
    encryptedFile = result.file;
    currentCryptoKey = result.key;
    currentSalt = result.salt;
    const blob = new Blob([`${JSON.stringify(result.file, null, 2)}\n`], { type: "application/json" });
    const downloadUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = downloadUrl;
    anchor.download = DATA_FILE;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(downloadUrl);
    if (rememberThisDevice) {
      try {
        await rememberCurrentKey(result.file);
      } catch {
        setNotice("Encrypted file downloaded, but this browser couldn’t update its saved key. You’ll need the passphrase again after this file is published.", true);
        return;
      }
    }
    setNotice("Encrypted file downloaded. Replace shows.enc.json in your GitHub repository with this download, then commit and push it.");
  } catch {
    setNotice("Encryption failed. Check that you’re using a secure, up-to-date browser and try again.", true);
  } finally {
    setBusy(button, false);
  }
});

document.querySelector("#lock-button").addEventListener("click", () => {
  currentPassphrase = "";
  currentCryptoKey = null;
  currentSalt = null;
  rememberThisDevice = false;
  shows = [];
  passphraseInput.value = "";
  confirmInput.value = "";
  watchlistPanel.hidden = true;
  lockPanel.hidden = false;
  setNotice("The list is locked in this browser.");
  passphraseInput.focus();
});

forgetDeviceButton.addEventListener("click", async () => {
  setBusy(forgetDeviceButton, true, "Forgetting…");
  try {
    await clearRememberedKey();
    forgetDeviceButton.hidden = true;
    rememberDeviceInput.checked = false;
    rememberThisDevice = false;
    setNotice("This browser’s saved unlock key has been removed. The shared encrypted list is unchanged.");
  } catch {
    setNotice("Could not remove the saved key from this browser. You can clear this site’s data in browser settings.", true);
  } finally {
    setBusy(forgetDeviceButton, false);
  }
});

loadEncryptedFile();
