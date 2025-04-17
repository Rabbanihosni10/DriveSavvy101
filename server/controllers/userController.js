import userModel from "../models/userModel.js";


export const getUserData=async(req,res)=>{
    try{
        const {userId} = req.body; // ✅ Get userId from authenticated user (req.user)
        const user = await userModel.findById(userId); // ✅ Don't forget await here!
        if(!user){
            return res.json({success:false,message:'User not found'});
        }
        res.json({
            success:true,
            userData:{
                name:user.name,
                isUserVerified:user.isAccountVerified,
                email:user.email,
                phone:user.phone,
                role:user.role
            }
        })
    }
    catch(error){
        return res.json({success:false,message:error.message})
    }
}