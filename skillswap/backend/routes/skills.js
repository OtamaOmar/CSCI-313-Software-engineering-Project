import express from 'express';
import { pool } from '../db.js';
import { authenticateToken } from '../middleware.js';

const router = express.Router();

// Get all skills for authenticated user
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM skills WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get skills error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get skills by user ID
router.get('/user/:userId', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM skills WHERE user_id = $1 ORDER BY created_at DESC',
      [req.params.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get user skills error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add new skill
router.post('/', authenticateToken, async (req, res) => {
  try {
    const { skill_name, skill_type } = req.body;

    if (!skill_name || !skill_type) {
      return res.status(400).json({ error: 'Skill name and type are required' });
    }

    const result = await pool.query(
      'INSERT INTO skills (user_id, skill_name, skill_type) VALUES ($1, $2, $3) RETURNING *',
      [req.user.id, skill_name, skill_type]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Add skill error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update skill
router.put('/:id', authenticateToken, async (req, res) => {
  try {
    const { skill_name, skill_type } = req.body;

    const result = await pool.query(
      `UPDATE skills 
       SET skill_name = COALESCE($1, skill_name),
           skill_type = COALESCE($2, skill_type)
       WHERE id = $3 AND user_id = $4
       RETURNING *`,
      [skill_name, skill_type, req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Skill not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update skill error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete skill
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM skills WHERE id = $1 AND user_id = $2 RETURNING *',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Skill not found' });
    }

    res.json({ message: 'Skill deleted successfully' });
  } catch (error) {
    console.error('Delete skill error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

export default router;
