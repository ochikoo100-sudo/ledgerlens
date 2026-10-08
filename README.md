# Ledger & Lens — game server

This folder is the whole online version of the game:

- `public/index.html`: the game itself
- `server.js`: live Showdowns, firm chat, the online list, firm rankings and cloud saves

When it's running, anyone who opens your server's link gets everything. A downloaded copy of the game from that link also connects back to your server automatically.

## Deploy it free on Render (about 15 minutes)

### 1. Put the files on GitHub
1. Make a free account at https://github.com.
2. Click **New repository**, name it `ledger-lens`, and click **Create repository**.
3. Click **uploading an existing file** and drag in everything in this folder:
   `server.js`, `package.json`, `render.yaml`, `.gitignore`, `README.md` and the `public` folder.
4. Click **Commit changes**.

### 2. Make a free database, so rankings are never lost
On the free plan, Render wipes its disk whenever the server restarts. A free Postgres database keeps the rankings and saves safe.
1. Make a free account at https://neon.tech and create a project.
2. Copy the **connection string**. It looks like `postgresql://user:pass@ep-xxx.neon.tech/neondb?sslmode=require`.

(Skip this step if you only want to try it out. The game still works, but rankings reset whenever the server restarts.)

### 3. Run it on Render
1. Make a free account at https://render.com and sign in with GitHub.
2. Click **New → Blueprint** and pick your `ledger-lens` repository. Render reads `render.yaml`.
3. When it asks for **DATABASE_URL**, paste your Neon connection string.
4. Click **Apply** and wait about 2–3 minutes for the build.
5. Your game is live at something like `https://ledger-lens.onrender.com`. Send that link to your friends.

## Good to know
- **The free Render plan sleeps after 15 minutes with nobody playing.** The first visit afterwards takes about 30–50 seconds to wake it up, and then it runs normally.
- **Updating the game:** replace `public/index.html` on GitHub with a new version. Render redeploys by itself.
- **Running it on your own computer:** install Node 18+, then run `npm install` and `npm start`, and open http://localhost:3000.
- **Other hosts** (Railway, Fly.io, a VPS) work too. Run `npm start`, and optionally set `DATABASE_URL`. Without it, data is saved to `data/db.json`.
