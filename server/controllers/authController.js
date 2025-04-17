//will be use to control- register, login, logout, verify account, password reset
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';

// Register User

export const Register =async(req,res)=>{
    const {name,email,phone,password,role}=req.body;
    if(!name || !email || !phone || !password || !role){
        return res.json({success:false, message: 'Missing required details'})
    }
    try{
        // check if user is exist or not
        const existingUser=await userModel.findOne({email})
        if(existingUser){
            return res.json({success:false,message: "User Already Exists!"});
        }
        // bcrypt the password
        const hashedPassword=await bcrypt.hash(password,10);
        //save under user const as new userModel
        const user=new userModel({
            name,
            email,
            phone,
            password:hashedPassword,
            role
        });
        // save the user to the database
        await user.save();

        //genarate the token as new user
        const token= jwt.sign({id:user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});

        res.cookie('token',token,{
            httpOnly:true,
            secure: process.env.NODE_ENV=== 'Production',
            sameSite: process.env.NODE_ENV=== 'Production'?'None':'strict',
            maxAge: 7*24*60*60*1000 // 7days
        });

        //sent an email
        const mailOptions={
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Drive Savvy',
            text:`Welcome to DriveSavvy. Your account has been created with email id:${email}`
        }

        await transporter.sendMail(mailOptions);

        return res.json({success:true,message: "User Registerd"})
    }
    catch(error){
        res.json({success:false,message: error.message})        
    }
}

// Login User

export const Login= async(req,res)=>{
    const {email,password}=req.body;

    if(!email || !password){
        return res.json({success:false,message:'Email and Password are Required!'})
    }
    try{
        const user=await userModel.findOne({email});
        if(!user){
            return res.json({success:false,message: 'Invalid Email'})
        }
        
        const isMatch= await bcrypt.compare(password,user.password);
        
        if(!isMatch){
            return res.json({success:false,message: 'Invalid Password'})
        }
        //gen new token for user authentication
        const token=jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});
        res.cookie('token',token,{
            httpOnly: true,
            secure: process.env.NODE_ENV==='Production',
            sameSite: process.env.NODE_ENV==='Production'? 'none':'strict',
            maxAge: 7*24*60*60*1000
        })
        return res.json({success:true})
    }
    catch(error){
        return res.json({success:false,message: error.message})
    }
}

// Logout User

export const Logout=async(req,res)=>{
    try{
        res.clearCookie('token',{
            httpOnly: true,
            secure: process.env.NODE_ENV==='Production',
            sameSite: process.env.NODE_ENV==='Production'?'none':'strict'
        })
        return res.json({success:true,message: "Logged OUT"});
    }
    catch(error){
        return res.json({success:false,message:error.message})
    }
}

// Send verification otp to user email

export const SendVerifyOTP=async(req,res)=>{
    try{
        const {userId}=req.body;

        const user=await userModel.findById(userId);

        if(user.isAccountVerified){
            return res.json({success: false, message:'Account is already verified'})
        }

        const otp= String(Math.floor(100000+ Math.random()*900000));
        user.verifyOTP=otp;
        user.verifyOTPExpireAt=Date.now()+24*60*60*1000;


        await user.save();
        const mailOption={
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification',
            text: `Your OTP is ${otp}. Verify your account with this OTP. Thank Your!`
        }
        await transporter.sendMail(mailOption);
    }
    catch(error){
        return res.json({success:false,message:error.message})
    }
}

// Verify Email

export const verifyEmail=async(req,res)=>{
    const {userId,otp}=req.body;
    if(!userId || !otp){
    return res.json({success:false,message:'Missing Details!'})
    }
    try{
        const user= await userModel.findById(userId);
        if(!user){
            return res.json({success:false,message: "User Not Found!"})
        }
        if(user.verifyOTP === '' || user.verifyOTP !=otp){
           return res.json({success:false,message:`Invalid OTP` })
        }
        if(user.verifyOTPExpireAt<Date.now()){
            return res.json({success:false,message:`OTP Expired!`})
        }
        user.isAccountVerified=true;
        user.verifyOtp='';
        user.verifyOtpExpireAt=0;
        await user.save();
        return res.json({success:true,mesage:'Email Verrified Successfully!'})
    }
    catch(error){
       return res.json({success:false,message:error.message});
    }   
}


// Check if user is authenticated or not

export const isAuthenticated=async(req,res)=>{
    try{
        return res.json({success:true});
    }
    catch(error){
        res.json({success:false, message:error.message});
    }
}

// Send password reset OTP

export const sendResetOTP=async(req,res)=>{
    const {email}=req.body;   
    if(!email){
        return res.json({success:false,message:'Email is Required!'})
    }
    try{
        const user=await userModel.findOne({email});
        if(!user){
            return res.json({success:false,message:'User Not Found!'});
        }
        const otp=String(Math.floor(100000+Math.random()*900000));
        user.resetOTP=otp;
        user.restOtpExpireAt=Date.now()+10*60*1000;

        await user.save();
        const mailOption={
            from: process.env.SENDER_EMAIL,
            to:user.email,
            subject: "Password Reset OTP",
            text: `Your OTP is ${resetOTP}. Use this OTP to reset your password.`
        }
        await transporter.sendMail(mailOption);
        return res.json({success:true,message: 'OTP sent to your email!'});
    }
    catch(error){
        return res.json({success:false,message:error.message});
    }
}

// Reset user password

export const resetPassword= async(req,res)=>{
    const {email,otp,newPassword}=req.body;

    if(!email || !otp || !newPassword){
        return res.json({success:false,message:"Email,OTP and new Password are required!"});
    }
    try{
        const user=await userModel.findOne({email});
        if(!user){
            return res.json({success:false,message:"User Not Found!"});
        }
        if(user.resetOTP === '' || user.resetOTP != otp){
            return res.json({success:false,message:"Invalid OTP"});
        }
        if(user.resetOtpExpireAt<Date.now()){
            return res.json({success:false,message:"OTP Expired!"});
        }
        const hashedPassword=await bcrypt.hash(newPassword,10);
        user.password=hashedPassword;
        user.resetOTP='';
        user.resetOtpExpireAt=0;
        await user.save();

    }
    catch(error){
        return res.json({success:false,message:error.message});
    }
}

//   
     
     