import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { pool } from "../db.js";
import dotenv from "dotenv";

dotenv.config();

export const registerUser = async (req, res) => {
    const { username, email, password, full_name } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            "INSERT INTO profiles (username, email, full_name, role) VALUES ($1,$2,$3,'user') RETURNING id, username, email, full_name, role, created_at",
            [username, email, full_name]
        );

        res.json(result.rows[0]);

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

export const loginUser = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await pool.query("SELECT * FROM profiles WHERE email=$1", [email]);

        if (user.rows.length === 0)
            return res.status(400).json({ message: "No such user" });

        const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET);

        res.json({ token, user: user.rows[0] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

export const getAllUsers = async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, username, full_name, avatar_url, email, role, created_at FROM profiles ORDER BY created_at DESC"
        );
        res.json(result.rows);
    } catch (err) {
        console.error("getAllUsers error:", err);
        res.status(500).json({ error: err.message });
    }
};