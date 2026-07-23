const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { ObjectId } = require('mongodb');
const { connectToDatabase } = require('../models/db');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'giftlink-secret';

// Register
router.post('/register', async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;

        const db = await connectToDatabase();
        const users = db.collection('users');

        const existingUser = await users.findOne({ email });

        if (existingUser) {
            return res.status(400).json({
                error: 'User already exists'
            });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const result = await users.insertOne({
            firstName,
            lastName,
            email,
            password: hashedPassword
        });

        const token = jwt.sign(
            {
                id: result.insertedId,
                email
            },
            JWT_SECRET
        );

        res.json({
            authtoken: token,
            email
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: 'Server Error'
        });
    }
});

// Login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const db = await connectToDatabase();
        const users = db.collection('users');

        const user = await users.findOne({ email });

        if (!user) {
            return res.status(400).json({
                error: 'Invalid credentials'
            });
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(400).json({
                error: 'Invalid credentials'
            });
        }

        const token = jwt.sign(
            {
                id: user._id,
                email: user.email
            },
            JWT_SECRET
        );

        res.json({
            authtoken: token,
            firstName: user.firstName,
            email: user.email
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: 'Server Error'
        });
    }
});

// Update user information
router.put('/update-user-info', async (req, res) => {
    try {

        const token = req.header('Authorization');

        if (!token) {
            return res.status(401).json({
                error: 'Access denied'
            });
        }

        const decoded = jwt.verify(
            token.replace('Bearer ', ''),
            JWT_SECRET
        );

        const db = await connectToDatabase();
        const users = db.collection('users');

        const updateFields = {};

        if (req.body.firstName) {
            updateFields.firstName = req.body.firstName;
        }

        if (req.body.lastName) {
            updateFields.lastName = req.body.lastName;
        }

        if (req.body.email) {
            updateFields.email = req.body.email;
        }

        await users.updateOne(
            {
                _id: new ObjectId(decoded.id)
            },
            {
                $set: updateFields
            }
        );

        const updatedUser = await users.findOne({
            _id: new ObjectId(decoded.id)
        });

        res.json(updatedUser);

    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: 'Server Error'
        });
    }
});

module.exports = router;