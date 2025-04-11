import express from 'express';
import { Login, Logout, Register } from '../controllers/authController.js';


const authRouter=express.Router();

//Created endpoints for user authentication
authRouter.post('/register', Register);
authRouter.post('/login',Login);
authRouter.post('/logout',Logout);

export default authRouter;
