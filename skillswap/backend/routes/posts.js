import express from 'express';
import { pool } from '../db.js';
import { authenticateToken } from '../middleware.js';

const router = express.Router();

// Get all posts
router.get('/', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, 
              pr.username, pr.full_name, pr.avatar_url,
              COUNT(DISTINCT l.id) as likes_count,
              COUNT(DISTINCT c.id) as comments_count,
              COUNT(DISTINCT s.id) as shares_count,
              (SELECT COUNT(*) > 0 FROM likes WHERE post_id = p.id AND user_id = $1) as user_liked
       FROM posts p
       LEFT JOIN profiles pr ON p.user_id = pr.id
       LEFT JOIN likes l ON p.id = l.post_id
       LEFT JOIN comments c ON p.id = c.post_id
       LEFT JOIN shares s ON p.id = s.post_id
       GROUP BY p.id, pr.id
       ORDER BY p.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user posts
router.get('/user/:userId', async (req, res) => {
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
      [req.params.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get user posts error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create post
router.post('/', authenticateToken, async (req, res) => {
  try {
    const { content, image_url } = req.body;

    if (!content) {
      return res.status(400).json({ error: 'Content is required' });
    }

    const result = await pool.query(
      `INSERT INTO posts (user_id, content, image_url)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [req.user.id, content, image_url || null]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get comments for a post
router.get('/:id/comments', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*, pr.username, pr.full_name, pr.avatar_url
       FROM comments c
       LEFT JOIN profiles pr ON c.user_id = pr.id
       WHERE c.post_id = $1
       ORDER BY c.created_at DESC`,
      [req.params.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get comments error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add comment to post
router.post('/:id/comment', authenticateToken, async (req, res) => {
  try {
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({ error: 'Content is required' });
    }

    const result = await pool.query(
      `INSERT INTO comments (user_id, post_id, content)
       VALUES ($1, $2, $3)
       RETURNING id, user_id, post_id, content, created_at`,
      [req.user.id, req.params.id, content]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Like post
router.post('/:id/like', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO likes (user_id, post_id)
       VALUES ($1, $2)
       ON CONFLICT DO NOTHING`,
      [req.user.id, req.params.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Like post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Unlike post
router.delete('/:id/like', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM likes WHERE user_id = $1 AND post_id = $2',
      [req.user.id, req.params.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Unlike post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

export default router;
