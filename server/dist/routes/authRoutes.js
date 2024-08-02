"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const express_1 = require("express");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const joi_1 = __importDefault(require("joi"));
const router = (0, express_1.Router)();
const prisma = new client_1.PrismaClient();
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
    const token = jsonwebtoken_1.default.sign({ userId: value.id, userName: value.userName }, 'SECRET_KEY', {
        expiresIn: '5m'
    });
    res.cookie('jwt', token, { httpOnly: true, secure: true, maxAge: 60 * 1000 });
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
    const token = jsonwebtoken_1.default.sign({ userId: user.id, userName: user.userName }, 'SECRET_KEY', {
        expiresIn: '5m'
    });
    res.cookie('jwt', token, { httpOnly: true, secure: false, maxAge: 300000 });
    res.json(user);
});
exports.default = router;
