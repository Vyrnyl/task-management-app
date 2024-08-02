import { PrismaClient } from '@prisma/client';
import { Router, Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import Joi from 'joi';

const router = Router();
const prisma = new PrismaClient();

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

    const token = jwt.sign({ userId: value.id, userName: value.userName }, 'SECRET_KEY', {
        expiresIn: '5m'
    });
    
    res.cookie('jwt', token, { httpOnly: true, secure: true, maxAge:  60 * 1000});

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

    const token = jwt.sign({ userId: user.id, userName: user.userName }, 'SECRET_KEY', {
        expiresIn: '5m'
    });
    
    res.cookie('jwt', token, { httpOnly: true, secure: false, maxAge:  300000});

    res.json(user);
});




export default router;