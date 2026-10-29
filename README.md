# Our Watchlist

A small static site for sharing a family watchlist of IMDb links. The list is encrypted in each visitor's browser before it is downloaded and committed; GitHub Pages serves only the encrypted file.

**Website:** [Our Watchlist](https://aku911.github.io/stuff-to-watch/) (available after GitHub Pages is enabled for this repository; see setup below).

## How it works

- The site uses the browser's built-in Web Crypto API: AES-256-GCM encryption with a random salt and IV, and PBKDF2-SHA-256 (600,000 iterations) to derive the key from the passphrase.
- The passphrase and decrypted list stay in browser memory. They are never uploaded or saved in browser storage.
- The encrypted file, `shows.enc.json`, is public if the repository/site is public. Its contents are not readable without the family passphrase.
- This is client-side encryption, not a private hosting service. Use a long, unique passphrase and share it with family separately (not in the repository or alongside the encrypted file). Anyone with the file can attempt guesses offline.
- Do not commit an unencrypted export or put the passphrase in the site code. Replacing the encrypted file does not erase older encrypted versions from Git history.

## First-time setup

1. Push this repository to GitHub.
2. In the repository, open **Settings → Pages** and publish from the `main` branch and `/ (root)` folder (adjust the branch if needed).
3. Open the published site over HTTPS. On the first visit, choose a strong passphrase of at least 12 characters and confirm it.
4. Add shows and movies using their IMDb title links, then select **Encrypt & download**.
5. Replace the repository's `shows.enc.json` with the downloaded file, commit, and push. If the file does not exist yet, create it in the repository from the download.
6. Give family the Pages URL and share the passphrase through a separate trusted channel.

After the encrypted file is published, family members enter the same passphrase to unlock and view it. To change the list, unlock it, make edits, download the newly encrypted file, and commit that file to GitHub.

## Local preview

The Web Crypto API requires a secure context. GitHub Pages provides HTTPS; for local testing, serve the repository with a local static web server rather than opening `index.html` directly. No build step or external JavaScript package is required.
