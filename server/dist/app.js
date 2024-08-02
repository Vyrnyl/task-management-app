"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const client_1 = require("@prisma/client");
const cors_1 = __importDefault(require("cors"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const authRoutes_1 = __importDefault(require("./routes/authRoutes"));
const prisma = new client_1.PrismaClient();
const app = (0, express_1.default)();
//MIDDLEWARE  
app.use((0, cookie_parser_1.default)());
app.use(express_1.default.json());
app.use((0, cors_1.default)());
//ROUTES
app.use('/auth', authRoutes_1.default);
app.get('/jset', (req, res) => {
    console.log(req.cookies.jwt);
    res.json({ cookie: req.cookies });
});
const PORT = process.env.PORT || 8000;
app.listen(8000, () => console.log(`Server running on PORT: ${PORT}`));
