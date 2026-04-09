# VaultMesh - Zero-Knowledge Secure File Sharing

VaultMesh is a full-stack privacy-first file sharing website.

- Frontend: React + Vite
- Backend: Node.js + Express
- Storage mode: Atlas (recommended) or local fallback
- Crypto model: client-side AES-GCM encryption/decryption

## Core capabilities

- Browser-side file encryption before upload
- Ciphertext-only storage on backend
- Secure links with expiration, password, one-time, max-download, and revoke controls
- Recipient-side in-browser decryption
- Integrity verification using SHA-256 hash checks
- Access attempt logs and API rate limiting

## Project structure

- client/: React web app
- server/: Express API
- render.yaml: Render blueprint for backend deployment
- docker-compose.yml: Local containerized run

## Atlas setup (first step)

1. Create a MongoDB Atlas project and cluster.
2. Create a database user with read/write access.
3. In Network Access, allow your IP (and later Render outbound access).
4. Copy the connection string URI.
5. Configure backend env:

```powershell
Copy-Item .\server\.env.example .\server\.env
```

Edit server/.env and set:

- MONGODB_URI=<your Atlas connection string>
- MONGODB_DB_NAME=vaultmesh
- MONGODB_STATE_COLLECTION=vaultmesh_state

6. Start backend and verify:

```powershell
npm.cmd --prefix server install
npm.cmd --prefix server run dev
```

Check health endpoint:

- http://localhost:5000/api/health

You should see storageMode set to atlas.

## Local development

### Prerequisites

- Node.js 20+
- npm

### Configure env files

```powershell
Copy-Item .\server\.env.example .\server\.env
Copy-Item .\client\.env.example .\client\.env
```

### Run frontend + backend together

```powershell
npm.cmd install
npm.cmd run install:all
npm.cmd run dev
```

This starts:

- Frontend: http://localhost:5173
- Backend: http://localhost:5000

## Deploy backend on Render

1. Push this repository to GitHub.
2. In Render, create a new Web Service from that repo.
3. Use settings:
	- Root Directory: server
	- Build Command: npm install
	- Start Command: npm run start
4. Add environment variables in Render:
	- JWT_SECRET
	- CLIENT_ORIGIN (your Vercel domain)
	- MONGODB_URI (Atlas URI)
	- MONGODB_DB_NAME=vaultmesh
	- MONGODB_STATE_COLLECTION=vaultmesh_state
	- MAX_UPLOAD_BYTES=536870912
5. Deploy and verify:
	- https://your-render-service.onrender.com/api/health

## Deploy frontend on Vercel

1. Import the same GitHub repository in Vercel.
2. Set Root Directory to client.
3. Framework preset: Vite.
4. Build command: npm run build.
5. Output directory: dist.
6. Add env variable:
	- VITE_API_BASE_URL=https://your-render-service.onrender.com
7. Deploy.

## Final production wiring

After Vercel deploy is ready:

1. Copy your Vercel URL.
2. Update Render CLIENT_ORIGIN with that URL.
3. If needed, include multiple origins separated by commas.
4. Redeploy Render.

## Security notes

- Decryption keys are never sent to backend.
- Key fragment (#k=...) stays client-side.
- Replace JWT_SECRET with a strong secret in production.
