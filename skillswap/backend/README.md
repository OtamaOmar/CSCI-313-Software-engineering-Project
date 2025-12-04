# SkillSwap Backend

Node.js + Express backend with Supabase authentication and PostgreSQL database.

## Features

- **Supabase Authentication**: User signup, login, logout, and session management
- **PostgreSQL Database**: Direct database access for complex queries
- **RESTful API**: Complete CRUD operations for all resources
- **JWT Token Management**: Secure authentication with access and refresh tokens
- **CORS Enabled**: Configured for frontend communication

## Tech Stack

- Node.js + Express
- Supabase (Authentication & Database)
- PostgreSQL (via Supabase)
- Axios (HTTP client)
- dotenv (Environment variables)

## Setup

### 1. Install Dependencies

```bash
cd backend
npm install
```

### 2. Configure Environment Variables

Create a `.env` file in the backend directory:

```env
# Server Configuration
PORT=4000
NODE_ENV=development
FRONTEND_URL=http://localhost:5173

# Supabase Configuration
SUPABASE_URL=your_supabase_project_url
SUPABASE_ANON_KEY=your_supabase_anon_key

# Database Configuration (Supabase PostgreSQL)
DATABASE_URL=postgresql://user:password@host:port/database?sslmode=require

# JWT Secret (Optional - Supabase handles auth)
JWT_SECRET=your_jwt_secret_key_here
```

### 3. Get Supabase Credentials

1. Go to [Supabase Dashboard](https://supabase.com/dashboard)
2. Create a new project or select existing one
3. Go to **Settings** > **API**
4. Copy:
   - Project URL → `SUPABASE_URL`
   - anon/public key → `SUPABASE_ANON_KEY`
5. Go to **Settings** > **Database**
6. Copy Connection String (URI) → `DATABASE_URL`

### 4. Database Schema

Run the SQL script in Supabase SQL Editor:

```sql
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Profiles table
CREATE TABLE IF NOT EXISTS profiles (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username TEXT UNIQUE NOT NULL,
  full_name TEXT,
  email TEXT UNIQUE NOT NULL,
  avatar_url TEXT,
  role TEXT DEFAULT 'user',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Skills table
CREATE TABLE IF NOT EXISTS skills (
  id SERIAL PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  skill_name VARCHAR(255) NOT NULL,
  skill_type VARCHAR(50) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Posts table
CREATE TABLE IF NOT EXISTS posts (
  id SERIAL PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  image_url VARCHAR(500),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Comments table
CREATE TABLE IF NOT EXISTS comments (
  id SERIAL PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Likes table
CREATE TABLE IF NOT EXISTS likes (
  id SERIAL PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, post_id)
);

-- Shares table
CREATE TABLE IF NOT EXISTS shares (
  id SERIAL PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Friendships table
CREATE TABLE IF NOT EXISTS friendships (
  id SERIAL PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  friend_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  status VARCHAR(50) DEFAULT 'pending',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_posts_user_id ON posts(user_id);
CREATE INDEX idx_skills_user_id ON skills(user_id);
CREATE INDEX idx_comments_post_id ON comments(post_id);
CREATE INDEX idx_likes_post_id ON likes(post_id);
CREATE INDEX idx_friendships_user_id ON friendships(user_id);
```

### 5. Start the Server

```bash
npm start
```

The server will run on `http://localhost:4000`

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/signup` | Register new user |
| POST | `/api/auth/login` | Login user |
| POST | `/api/auth/logout` | Logout user |
| POST | `/api/auth/refresh` | Refresh access token |

### Users

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/users` | Get all users | No |
| GET | `/api/users/me` | Get current user | Yes |
| GET | `/api/users/:id` | Get user by ID | Yes |
| PUT | `/api/users/me` | Update profile | Yes |

### Posts

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/posts` | Get all posts | Yes |
| GET | `/api/posts/user/:userId` | Get user posts | No |
| POST | `/api/posts` | Create post | Yes |
| GET | `/api/posts/:id/comments` | Get post comments | No |
| POST | `/api/posts/:id/comment` | Add comment | Yes |
| POST | `/api/posts/:id/like` | Like post | Yes |
| DELETE | `/api/posts/:id/like` | Unlike post | Yes |

### Skills

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/skills/me` | Get my skills | Yes |
| GET | `/api/skills/user/:userId` | Get user skills | No |
| POST | `/api/skills` | Add skill | Yes |
| PUT | `/api/skills/:id` | Update skill | Yes |
| DELETE | `/api/skills/:id` | Delete skill | Yes |

### Friendships

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/friendships` | Get all friendships | Yes |
| POST | `/api/friendships/request` | Send friend request | Yes |
| PUT | `/api/friendships/:id/accept` | Accept request | Yes |
| DELETE | `/api/friendships/:id/reject` | Reject request | Yes |
| DELETE | `/api/friendships/:friendId` | Unfriend | Yes |

## Request/Response Examples

### Signup

```bash
curl -X POST http://localhost:4000/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "username": "johndoe",
    "full_name": "John Doe"
  }'
```

### Login

```bash
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

### Create Post

```bash
curl -X POST http://localhost:4000/api/posts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "content": "My first post!",
    "image_url": "https://example.com/image.jpg"
  }'
```

## Project Structure

```
backend/
├── routes/
│   ├── users.js          # User endpoints
│   ├── posts.js          # Post endpoints
│   ├── skills.js         # Skills endpoints
│   ├── friendships.js    # Friendship endpoints
│   └── userRoutes.js     # Legacy routes
├── controllers/
│   └── userControllers.js
├── middleware.js         # Auth middleware
├── db.js                # Database connection
├── server.js            # Main server file
├── package.json
└── .env                 # Environment variables
```

## Troubleshooting

### Port Already in Use

If you get `EADDRINUSE` error:

```bash
# Find process using port 4000
lsof -ti:4000

# Kill the process
lsof -ti:4000 | xargs kill -9
```

### Database Connection Issues

1. Verify your `DATABASE_URL` is correct
2. Check if Supabase project is active
3. Ensure you're using the correct pooling mode (Transaction vs Session)

### Authentication Issues

1. Verify `SUPABASE_URL` and `SUPABASE_ANON_KEY` are correct
2. Check if tokens are properly stored in frontend
3. Ensure Authorization header format: `Bearer <token>`

## Development

### Run with nodemon (auto-reload)

```bash
npm install -g nodemon
nodemon server.js
```

### Test API with curl

```bash
# Health check
curl http://localhost:4000/

# Get all users
curl http://localhost:4000/api/users
```

## License

MIT
