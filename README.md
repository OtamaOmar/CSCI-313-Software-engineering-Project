# SkillSwap

A simple peer-to-peer learning platform concept for students to teach each other skills — coding, design, languages, and more.

💼 Project idea

Students list skills they can teach and skills they want to learn. The platform connects peers for short lessons, study sessions, code reviews, and practice.

Why this project exists
- Learn-by-teaching accelerates learning.
- Lightweight, community-driven exchange with minimal overhead.
- Good full-stack learning project: frontend (React + Vite + Tailwind), backend (Node/Express + PostgreSQL), deployment-ready.

Quick demo goals
- Register/login (local auth or mocked for MVP)
- Create a profile with skills to teach/learn
- Search or browse peers by skill
- Message or schedule quick sessions (MVP: simple request flow)

Tech stack (what's in this repo)
- Frontend: React, Vite, Tailwind CSS (configured via PostCSS)
- Backend: Node.js (Express) with PostgreSQL (psycopg2 listed for python helpers)
- Dev environment: conda environment named `skillswap` (optional) for consistent Node/Python tooling

Quick start (development)

Prerequisites
- conda (optional but recommended for this repo)
- git

Create & activate the conda environment (optional)

```bash
conda create -n skillswap python=3.12 nodejs=22 -c conda-forge -y
conda activate skillswap
```

Frontend

```bash
cd skillswap/frontend
npm install
# Start dev server (Vite will process Tailwind via PostCSS)
npm run dev
```

Backend

```bash
cd skillswap/backend
npm install
# Start the server (or use nodemon during development)
node server.js
# or if you have nodemon configured
npm run dev
```

Database
- This repo assumes PostgreSQL is available if you use the backend with a real DB. Use the `psql` client or a Docker container for local development.
- Example .env values (create `skillswap/backend/.env`):

```env
DATABASE_URL=postgresql://user:password@localhost:5432/skillswap_db
PORT=4000
JWT_SECRET=your_secret_here
```

Tailwind notes
- Tailwind and PostCSS are already configured in `frontend/tailwind.config.cjs` and `frontend/postcss.config.cjs`.
- The main CSS entry is `frontend/src/index.css` and includes the Tailwind directives. Vite handles PostCSS processing during `npm run dev` and `npm run build`.

Git / pushing changes
- We recommend using SSH for GitHub pushes. If you haven't added an SSH key, generate one with `ssh-keygen -t ed25519` and add the public key in GitHub → Settings → SSH and GPG keys.
- The repository currently uses `main` as the primary branch.

Contributing
- Create a small branch for feature work, push to origin, and open a Pull Request. Keep changes focused and add tests where reasonable.

License & contact
- Add your preferred license file if you plan to open-source this project.
- For questions about this repo, contact the team lead.

Enjoy building SkillSwap! 🚀
