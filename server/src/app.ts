import express, { NextFunction, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/authRoutes';

const prisma = new PrismaClient();

const app = express();

//MIDDLEWARE  
app.use(cookieParser());
app.use(express.json());
app.use(cors());

//ROUTES
app.use('/auth', authRoutes);


app.get('/jset', (req, res) => {
    console.log(req.cookies.jwt);
    
    res.json({cookie: req.cookies});
});

const PORT = process.env.PORT || 8000;



app.listen(8000, () => console.log(`Server running on PORT: ${PORT}`));