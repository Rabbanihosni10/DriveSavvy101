//will be use to control- register, login, logout, verify account, password reset
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';

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
        })
        return res.json({success:true,message: "User Registerd"})
    }
    catch(error){
        res.json({success:false,message: error.message})        
    }
}


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