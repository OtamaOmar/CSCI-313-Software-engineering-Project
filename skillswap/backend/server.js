import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from '@supabase/supabase-js';
import userRoutes from "./routes/userRoutes.js";
import usersRoutes from "./routes/users.js";
import postsRoutes from "./routes/posts.js";
import skillsRoutes from "./routes/skills.js";
import friendshipsRoutes from "./routes/friendships.js";

dotenv.config();

const app = express();

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true
}));

app.use(express.json());

const PORT = process.env.PORT || 4000;

// Initialize Supabase client
export const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// Basic health check
app.get("/", (req, res) => {
  res.json({ 
    message: "SkillSwap Backend API",
    status: "running",
    timestamp: new Date().toISOString()
  });
});

// Auth routes
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password, username, full_name } = req.body;
    
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          username,
          full_name
        }
      }
    });

    if (error) throw error;
    res.status(201).json({ user: data.user, session: data.session });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) throw error;
    res.json({ user: data.user, session: data.session });
  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({ error: error.message });
  }
});

app.post("/api/auth/logout", async (req, res) => {
  try {
    const { error } = await supabase.auth.signOut();
    if (error) throw error;
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/auth/refresh", async (req, res) => {
  try {
    const { refresh_token } = req.body;
    const { data, error } = await supabase.auth.refreshSession({ refresh_token });
    
    if (error) throw error;
    res.json({ session: data.session });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(401).json({ error: error.message });
  }
});

// API Routes
app.use("/api/users", usersRoutes);
app.use("/api/posts", postsRoutes);
app.use("/api/skills", skillsRoutes);
app.use("/api/friendships", friendshipsRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error'
  });
});

app.listen(PORT, () => {
  console.log(`SkillSwap backend running on http://localhost:${PORT}`);
});