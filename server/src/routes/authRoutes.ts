import { PrismaClient } from '@prisma/client';
import { Router, Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import Joi from 'joi';

dotenv.config();

const router = Router();
const prisma = new PrismaClient();

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET!;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET!;

router.post('/signup', async (req: Request, res: Response) => {
    

    //VALIDATION
    const signupSchema = Joi.object({
        firstName: Joi.string().max(50).required().messages({
            'string.empty': 'First Name cannot be empty',
            'string.base': 'First Name should be a type of text'
        }),
        lastName: Joi.string().max(50).required().messages({
            'string.empty': 'Last Name cannot be empty',
            'string.base': 'Last Name should be a type of text'
        }),
        userName: Joi.string().max(50).required().messages({
            'string.empty': 'Username cannot be empty'
        }),
        email: Joi.string().email({ tlds: { allow: false }}).required().messages({
            'string.empty': 'Email cannot be empty',
            'string.email': 'Please enter a valid email'
        }),
        password: Joi.string().min(6).required().messages({
            'string.empty': 'Password cannot be empty',
            'string.min': 'Password must be atleast 6 characters long'
        }),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required().messages({
            'string.empty': 'Confirm Password cannot be empty',
            'any.only': 'Password do not match'
        })
    });

    const { error, value } = signupSchema.validate(req.body, { abortEarly: false });

    if(error) {
        const err = error.details.map(err => {
            const error = { path: err['path'][0], error: err.message };
            return error;
        });
        return res.status(422).json({error: err});
    }


    //EMAIL DB VALIDATE
    const existingEmail = await prisma.user.findUnique({
        where: { email: value.email }
    });

    if(existingEmail) {
        return res.status(409).json({error: [{ path: 'email', error: 'Email already registered' }]});
    }

1
    //HASHING
    const hashPassword = await bcrypt.hash(value.password, 10);

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


    const accessToken = jwt.sign({ userId: user.id, userName: user.userName }, ACCESS_TOKEN_SECRET, {
        expiresIn: '5s'
    });
    const refreshToken = jwt.sign({ userId: user.id, userName: user.userName }, REFRESH_TOKEN_SECRET, {
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

    res.status(201).json({message: 'Success', data: user});
});


router.post('/login', async (req: Request, res: Response) => {
    
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({
        where: { email }
    });

    if(!user) {
        return res.json({ error: 'Invalid email or password' });
    }


    //COMPARE
    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if(!passwordMatch) {
        return res.json({ error: 'Invalid email or password' });
    }

    const accessToken = jwt.sign({ userId: user.id, userName: user.userName }, ACCESS_TOKEN_SECRET, {
        expiresIn: '5s'
    });
    const refreshToken = jwt.sign({ userId: user.id, userName: user.userName }, REFRESH_TOKEN_SECRET, {
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
    } catch(err) {
        console.log('Error');
    }

    res.json(user);
});


router.post('/logout', async (req: Request, res: Response) => {

    const refreshToken = req.headers['refresh-token'] as string;

    if(refreshToken === 'undefined' || !refreshToken) {
        return res.json({ error: 'Refresh Token Error' });
    }

    try {
        await prisma.refreshToken.delete({
            where: {
                token: refreshToken
            }
        });
        res.json({ message: 'Logout Successfully'});
    } catch(err) {
        return res.json({ error: 'Already logged out' });
    }
});


router.post('/refresh-token', async (req: Request, res: Response) => {

    const refreshToken = req.headers['refresh-token'] as string;

    if(refreshToken === 'undefined' || !refreshToken) {
        return res.json({error: 'No token provided'});
    }

    //CHECK DB
    const token = await prisma.refreshToken.findUnique({
        where: {
            token: refreshToken
        }
    });

    if(!token) {
        return res.json({ error: 'Refresh Token not found' });
    }

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, value) => {
        if(err) {
            return res.json({error: 'Refresh Token Error'});
        }
        res.json({ message: 'Token refreshed' });
    });

});


export default router;