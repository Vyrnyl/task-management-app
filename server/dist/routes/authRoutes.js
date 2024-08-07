"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const express_1 = require("express");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const dotenv_1 = __importDefault(require("dotenv"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const joi_1 = __importDefault(require("joi"));
dotenv_1.default.config();
const router = (0, express_1.Router)();
const prisma = new client_1.PrismaClient();
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
router.post('/signup', async (req, res) => {
    //VALIDATION
    const signupSchema = joi_1.default.object({
        firstName: joi_1.default.string().max(50).required().messages({
            'string.empty': 'First Name cannot be empty',
            'string.base': 'First Name should be a type of text'
        }),
        lastName: joi_1.default.string().max(50).required().messages({
            'string.empty': 'Last Name cannot be empty',
            'string.base': 'Last Name should be a type of text'
        }),
        userName: joi_1.default.string().max(50).required().messages({
            'string.empty': 'Username cannot be empty'
        }),
        email: joi_1.default.string().email({ tlds: { allow: false } }).required().messages({
            'string.empty': 'Email cannot be empty',
            'string.email': 'Please enter a valid email'
        }),
        password: joi_1.default.string().min(6).required().messages({
            'string.empty': 'Password cannot be empty',
            'string.min': 'Password must be atleast 6 characters long'
        }),
        confirmPassword: joi_1.default.string().valid(joi_1.default.ref('password')).required().messages({
            'string.empty': 'Confirm Password cannot be empty',
            'any.only': 'Password do not match'
        })
    });
    const { error, value } = signupSchema.validate(req.body, { abortEarly: false });
    if (error) {
        const err = error.details.map(err => {
            const error = { path: err['path'][0], error: err.message };
            return error;
        });
        return res.status(422).json({ error: err });
    }
    //EMAIL DB VALIDATE
    const existingEmail = await prisma.user.findUnique({
        where: { email: value.email }
    });
    if (existingEmail) {
        return res.status(409).json({ error: [{ path: 'email', error: 'Email already registered' }] });
    }
    1;
    //HASHING
    const hashPassword = await bcrypt_1.default.hash(value.password, 10);
    //DB STORE
    const user = await prisma.user.create({
        data: {
            firstName: value.firstName,
            lastName: value.lastName,
            userName: value.userName,
            email: value.email,
            password: hashPassword
        }
    });
    const accessToken = jsonwebtoken_1.default.sign({ userId: user.id, userName: user.userName }, ACCESS_TOKEN_SECRET, {
        expiresIn: '5s'
    });
    const refreshToken = jsonwebtoken_1.default.sign({ userId: user.id, userName: user.userName }, REFRESH_TOKEN_SECRET, {
        expiresIn: '5m'
    });
    res.set({
        'Authorization': `Bearer ${accessToken}`,
        'Refresh-Token': refreshToken
    });
    //STORE TOKEN
    const token = await prisma.refreshToken.create({
        data: {
            token: refreshToken,
            userId: user.id
        }
    });
    res.status(201).json({ message: 'Success', data: user });
});
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({
        where: { email }
    });
    if (!user) {
        return res.json({ error: 'Invalid email or password' });
    }
    //COMPARE
    const passwordMatch = await bcrypt_1.default.compare(password, user.password);
    if (!passwordMatch) {
        return res.json({ error: 'Invalid email or password' });
    }
    const accessToken = jsonwebtoken_1.default.sign({ userId: user.id, userName: user.userName }, ACCESS_TOKEN_SECRET, {
        expiresIn: '5s'
    });
    const refreshToken = jsonwebtoken_1.default.sign({ userId: user.id, userName: user.userName }, REFRESH_TOKEN_SECRET, {
        expiresIn: '5m'
    });
    res.set({
        'Authorization': `Bearer ${accessToken}`,
        'Refresh-Token': refreshToken
    });
    //STORE TOKEN
    try {
        const token = await prisma.refreshToken.create({
            data: {
                token: refreshToken,
                userId: user.id
            }
        });
    }
    catch (err) {
        console.log('Error');
    }
    res.json(user);
});
router.post('/logout', async (req, res) => {
    const refreshToken = req.headers['refresh-token'];
    if (refreshToken === 'undefined' || !refreshToken) {
        return res.json({ error: 'Refresh Token Error' });
    }
    try {
        await prisma.refreshToken.delete({
            where: {
                token: refreshToken
            }
        });
        res.json({ message: 'Logout Successfully' });
    }
    catch (err) {
        return res.json({ error: 'Already logged out' });
    }
});
router.post('/refresh-token', async (req, res) => {
    const refreshToken = req.headers['refresh-token'];
    if (refreshToken === 'undefined' || !refreshToken) {
        return res.json({ error: 'No token provided' });
    }
    //CHECK DB
    const token = await prisma.refreshToken.findUnique({
        where: {
            token: refreshToken
        }
    });
    if (!token) {
        return res.json({ error: 'Refresh Token not found' });
    }
    jsonwebtoken_1.default.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, value) => {
        if (err) {
            return res.json({ error: 'Refresh Token Error' });
        }
        res.json({ message: 'Token refreshed' });
    });
});
exports.default = router;
