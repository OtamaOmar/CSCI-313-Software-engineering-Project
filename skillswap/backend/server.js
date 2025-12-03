import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import userRoutes from "./routes/userRoutes.js";

dotenv.config();

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Missing SUPABASE_URL, SUPABASE_ANON_KEY or SUPABASE_SERVICE_ROLE_KEY in env');
  process.exit(1);
}

// Two clients: service (private) and anon (used for signing in)
const supabaseService = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
const supabaseAnon = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;

/**
 * Helper: extract access token from Authorization header
 */
function getBearerToken(req) {
  const h = req.headers.authorization || '';
  const parts = h.split(' ');
  if (parts.length === 2 && parts[0] === 'Bearer') return parts[1];
  return null;
}

/**
 * Signup:
 * - create user with admin.createUser (service role)
 * - insert row into profiles (id = user.id)
 * - sign in using anon client to get session (access/refresh token)
 */
app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password, username, full_name, avatar_url } = req.body;
    if (!email || !password || !username) {
      return res.status(400).json({ error: 'email, password and username are required' });
    }

    // 1) create user via admin API (service role)
    const createResp = await supabaseService.auth.admin.createUser({
      email,
      password,
      email_confirm: true, // create confirmed by default (adjust if you want email confirmations)
      user_metadata: { full_name }
    });

    if (createResp.error) {
      return res.status(400).json({ error: createResp.error.message || createResp.error });
    }
    const user = createResp.user;
    const userId = user.id;

    // 2) insert profile record
    const insertResp = await supabaseService
      .from('profiles')
      .insert([{
        id: userId,
        username,
        full_name: full_name || null,
        avatar_url: avatar_url || null,
        role: 'user'
      }]);

    if (insertResp.error) {
      // rollback: delete user to avoid orphan auth user if profile insert fails
      await supabaseService.auth.admin.deleteUser(userId).catch(() => {});
      return res.status(400).json({ error: insertResp.error.message || insertResp.error });
    }

    // 3) sign in to get session tokens
    const signInResp = await supabaseAnon.auth.signInWithPassword({
      email,
      password
    });

    if (signInResp.error) {
      return res.status(400).json({ error: signInResp.error.message || signInResp.error });
    }

    // Retrieve the profile to return
    const profileRow = await supabaseService
      .from('profiles')
      .select('*')
      .eq('id', userId)
      .single();

    return res.status(201).json({
      message: 'user created',
      user: {
        id: userId,
        email: user.email
      },
      session: signInResp.data?.session || null,
      profile: profileRow.data || null
    });
  } catch (err) {
    console.error('Signup error', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

/**
 * Login:
 * - sign in via anon client
 * - return session + profile
 */
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const signInResp = await supabaseAnon.auth.signInWithPassword({ email, password });
    if (signInResp.error) {
      return res.status(401).json({ error: signInResp.error.message || signInResp.error });
    }

    const session = signInResp.data?.session;
    const user = signInResp.data?.user;
    if (!user || !user.id) return res.status(500).json({ error: 'could not get user after sign-in' });

    // fetch profile using service role
    const profileResp = await supabaseService
      .from('profiles')
      .select('*')
      .eq('id', user.id)
      .single();

    return res.json({
      session,
      profile: profileResp.data || null
    });
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

/**
 * Get current user's profile (protected)
 * - expects Authorization: Bearer <access_token>
 */
app.get('/auth/profile', async (req, res) => {
  try {
    const token = getBearerToken(req);
    if (!token) return res.status(401).json({ error: 'missing access token in Authorization header' });

    // retrieve user from token using service client
    const getUserResp = await supabaseService.auth.getUser(token);
    if (getUserResp.error) return res.status(401).json({ error: getUserResp.error.message || getUserResp.error });

    const user = getUserResp.data?.user;
    if (!user) return res.status(401).json({ error: 'invalid token' });

    // fetch profile
    const profileResp = await supabaseService
      .from('profiles')
      .select('*')
      .eq('id', user.id)
      .single();

    if (profileResp.error) return res.status(404).json({ error: profileResp.error.message || profileResp.error });

    return res.json({ profile: profileResp.data });
  } catch (err) {
    console.error('Get profile error', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

/**
 * Update profile (protected)
 * - expects Authorization: Bearer <access_token>
 * - body: { username?, full_name?, avatar_url?, role? }
 */
app.put('/auth/profile', async (req, res) => {
  try {
    const token = getBearerToken(req);
    if (!token) return res.status(401).json({ error: 'missing access token in Authorization header' });

    const getUserResp = await supabaseService.auth.getUser(token);
    if (getUserResp.error) return res.status(401).json({ error: getUserResp.error.message || getUserResp.error });

    const user = getUserResp.data?.user;
    if (!user) return res.status(401).json({ error: 'invalid token' });

    const allowed = ['username', 'full_name', 'avatar_url', 'role'];
    const updates = {};
    for (const k of allowed) {
      if (k in req.body) updates[k] = req.body[k];
    }
    if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'no updatable fields provided' });

    // set updated_at
    updates.updated_at = new Date().toISOString();

    const updateResp = await supabaseService
      .from('profiles')
      .update(updates)
      .eq('id', user.id);

    if (updateResp.error) return res.status(400).json({ error: updateResp.error.message || updateResp.error });

    // fetch single
    const profileResp = await supabaseService.from('profiles').select('*').eq('id', user.id).single();
    return res.json({ profile: profileResp.data });
  } catch (err) {
    console.error('Update profile error', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// User routes from main branch
app.use("/api/users", userRoutes);

app.listen(PORT, () => {
  console.log(`SkillSwap backend running on http://localhost:${PORT}`);
});
