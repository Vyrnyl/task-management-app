import express, { NextFunction, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import cors from 'cors';
import jwt, {JwtPayload} from 'jsonwebtoken';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/authRoutes';

dotenv.config();

const prisma = new PrismaClient();

const app = express();

//MIDDLEWARE  
app.use(cookieParser());
app.use(express.json());
app.use(cors({
    exposedHeaders: ['Authorization', 'Refresh-Token']
}));

//ROUTES
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET!;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET!;

app.use('/auth', authRoutes);


const PORT = process.env.PORT || 8000;
app.listen(8000, () => console.log(`Server running on PORT: ${PORT}`));