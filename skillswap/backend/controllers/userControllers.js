import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { pool } from "../db.js";
import dotenv from "dotenv";

dotenv.config();

export const registerUser = async (req, res) => {
    const { name, email, password, skills } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            "INSERT INTO users (name, email, password, skills) VALUES ($1,$2,$3,$4) RETURNING *",
            [name, email, hashedPassword, skills]
        );

        res.json(result.rows[0]);

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

export const loginUser = async (req, res) => {
    const { email, password } = req.body;

    const user = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

    if (user.rows.length === 0)
        return res.status(400).json({ message: "No such user" });

    const match = await bcrypt.compare(password, user.rows[0].password);

    if (!match) return res.status(400).json({ message: "Wrong password" });

    const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET);

    res.json({ token, user: user.rows[0] });
};

export const getAllUsers = async (req, res) => {
    const result = await pool.query("SELECT id, name, skills FROM users");
    res.json(result.rows);
};