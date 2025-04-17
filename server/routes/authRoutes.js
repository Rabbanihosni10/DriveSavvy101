import express from 'express';
import { isAuthenticated, Login, Logout, Register, resetPassword, sendResetOTP, SendVerifyOTP, verifyEmail } from '../controllers/authController.js';
import userAuth from '../middlewares/authMiddleware.js';


const authRouter=express.Router();

//Created endpoints for user authentication
authRouter.post('/register', Register);
authRouter.post('/login',Login);
authRouter.post('/logout',Logout);
authRouter.post('/send-verify-otp',userAuth,SendVerifyOTP);
authRouter.post('/verify-account',userAuth,verifyEmail);
authRouter.post('/is-auth',userAuth,isAuthenticated);
authRouter.post('/send-reset-lt;',sendResetOTP);
authRouter.post('/reset-password',resetPassword);

 
export default authRouter;
