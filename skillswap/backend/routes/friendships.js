import express from 'express';
import { pool } from '../db.js';
import { authenticateToken } from '../middleware.js';

const router = express.Router();

// Get all friendships for current user
router.get('/', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT f.*, 
              pr.username, pr.full_name, pr.avatar_url
       FROM friendships f
       LEFT JOIN profiles pr ON 
         (CASE 
           WHEN f.user_id = $1 THEN f.friend_id 
           ELSE f.user_id 
         END) = pr.id
       WHERE f.user_id = $1 OR f.friend_id = $1
       ORDER BY f.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get friendships error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Send friend request
router.post('/request', authenticateToken, async (req, res) => {
  try {
    const { friend_id } = req.body;

    if (!friend_id) {
      return res.status(400).json({ error: 'Friend ID is required' });
    }

    if (friend_id === req.user.id) {
      return res.status(400).json({ error: 'Cannot send friend request to yourself' });
    }

    const result = await pool.query(
      `INSERT INTO friendships (user_id, friend_id, status)
       VALUES ($1, $2, 'pending')
       RETURNING *`,
      [req.user.id, friend_id]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Send friend request error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Accept friend request
router.put('/:id/accept', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE friendships 
       SET status = 'accepted'
       WHERE id = $1 AND friend_id = $2 AND status = 'pending'
       RETURNING *`,
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Friend request not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Accept friend request error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reject friend request
router.delete('/:id/reject', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM friendships 
       WHERE id = $1 AND (friend_id = $2 OR user_id = $2)
       RETURNING *`,
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Friend request not found' });
    }

    res.json({ message: 'Friend request deleted successfully' });
  } catch (error) {
    console.error('Reject friend request error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Unfriend
router.delete('/:friendId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM friendships 
       WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)
       RETURNING *`,
      [req.user.id, req.params.friendId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Friendship not found' });
    }

    res.json({ message: 'Unfriended successfully' });
  } catch (error) {
    console.error('Unfriend error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

export default router;
