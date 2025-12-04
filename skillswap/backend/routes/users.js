import express from 'express';
import { pool } from '../db.js';
import { authenticateToken } from '../middleware.js';

const router = express.Router();

// Get current user profile
router.get('/me', authenticateToken, async (req, res) => {
  try {
    // First check if profile exists
    let result = await pool.query(
      `SELECT id, username, email, full_name, avatar_url, role, created_at
       FROM profiles WHERE id = $1`,
      [req.user.id]
    );

    // If profile doesn't exist, create it from Supabase auth data
    if (result.rows.length === 0) {
      const username = req.user.username || req.user.email?.split('@')[0] || 'user';
      const full_name = req.user.full_name || req.user.name || '';
      
      result = await pool.query(
        `INSERT INTO profiles (id, username, email, full_name, role)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (id) DO UPDATE SET email = $3
         RETURNING id, username, email, full_name, avatar_url, role, created_at`,
        [req.user.id, username, req.user.email, full_name, 'user']
      );
    }

    const user = result.rows[0];

    // Get skills
    try {
      const skills = await pool.query(
        'SELECT id, skill_name, skill_type FROM skills WHERE user_id = $1 ORDER BY created_at DESC',
        [req.user.id]
      );
      user.skills = skills.rows;
    } catch (skillError) {
      console.warn('Skills table not found, returning empty array');
      user.skills = [];
    }

    res.json(user);
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ error: error.message || 'Server error' });
  }
});

// Get user by ID
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, full_name, avatar_url, email, role, created_at
       FROM profiles WHERE id = $1`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    // Get skills
    const skills = await pool.query(
      'SELECT id, skill_name, skill_type FROM skills WHERE user_id = $1 ORDER BY created_at DESC',
      [req.params.id]
    );

    user.skills = skills.rows;

    // Get stats
    const stats = await pool.query(
      `SELECT 
        (SELECT COUNT(*) FROM posts WHERE user_id = $1) as posts,
        (SELECT COUNT(*) FROM friendships WHERE user_id = $1 AND status = 'accepted') as following,
        (SELECT COUNT(*) FROM friendships WHERE friend_id = $1 AND status = 'accepted') as followers`,
      [req.params.id]
    );

    user.stats = stats.rows[0];
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users
router.get('/', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, full_name, avatar_url, email, role, created_at FROM profiles ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get all users error:', error);
    // If table doesn't exist, return empty array
    if (error.code === '42P01') {
      return res.json([]);
    }
    res.status(500).json({ error: error.message || 'Server error' });
  }
});

// Update user profile
router.put('/me', authenticateToken, async (req, res) => {
  try {
    const { full_name, bio, location, country } = req.body;

    const result = await pool.query(
      `UPDATE profiles 
       SET full_name = COALESCE($1, full_name),
           updated_at = NOW()
       WHERE id = $2
       RETURNING id, username, email, full_name, avatar_url, role, created_at`,
      [full_name, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user posts
router.get('/:id/posts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, 
              pr.username, pr.full_name, pr.avatar_url,
              COUNT(DISTINCT l.id) as likes_count,
              COUNT(DISTINCT c.id) as comments_count,
              COUNT(DISTINCT s.id) as shares_count
       FROM posts p
       LEFT JOIN profiles pr ON p.user_id = pr.id
       LEFT JOIN likes l ON p.id = l.post_id
       LEFT JOIN comments c ON p.id = c.post_id
       LEFT JOIN shares s ON p.id = s.post_id
       WHERE p.user_id = $1
       GROUP BY p.id, pr.id
       ORDER BY p.created_at DESC`,
      [req.params.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get user posts error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add skill
router.post('/skills', authenticateToken, async (req, res) => {
  try {
    const { skill_name, proficiency_level } = req.body;

    if (!skill_name) {
      return res.status(400).json({ error: 'Skill name is required' });
    }

    const result = await pool.query(
      `INSERT INTO skills (user_id, skill_name, skill_type)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, skill_name) DO NOTHING
       RETURNING id, skill_name, skill_type, proficiency_level`,
      [req.user.id, skill_name, proficiency_level || 'Intermediate']
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Skill already exists' });
    }

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Add skill error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete skill
router.delete('/skills/:skillId', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM skills WHERE id = $1 AND user_id = $2',
      [req.params.skillId, req.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Delete skill error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

export default router;
