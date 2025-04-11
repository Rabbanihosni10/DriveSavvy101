import mongoose from 'mongoose';

const userSchema= new mongoose.Schema({
    name: {type: String, required:true},
    email: {type: String, required:true, unique:true},
    phone: {type: Number, required:true, unique:true},
    password: {type: String, required:true},
    role: {type:String,required:true,default:'owner'},
    verifyOTP: {type: String, default:''},
    verifyOTPExpireAt: {type: Number, default:0},
    isAccountVerified: {type: Boolean, default:false},
    resetOtp: {type:String,default:''},
    resetOtpExpireAt: {type: Number, default:0},

})

const userModel=mongoose.models.user || mongoose.model('user',userSchema);

export default userModel;