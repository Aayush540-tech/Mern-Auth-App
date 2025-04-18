import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/user.models.js';
import transporter from '../config/nodemailer.js';



export const register = async(req,res)=>{
    const {name, email, password} = req.body;
    if(!name || !email || !password){
        return res.json({success:false,message:'missing details'})
    }
    try{
        const existingUser= await userModel.findOne({email});

        if(existingUser){
            return res.json({success:false, message:"user already exists please LOGIN"});
        }

        const hashedPassword = await bcrypt.hash(password,10);
        const user= new userModel({name,email,password:hashedPassword});
        await user.save()

        //generating token for authentication
        const token = jwt.sign({id:user._id},process.env.JWT_SECERT,{expiresIn:'7d'});

        //sending token to user in cookie form
        res.cookie('token',token, {
            httpOnly:true,
            secure: process.env.NODE_ENV==='production',
            sameSite: process.env.NODE_ENV==='production'?'none':'strict',
            maxAge: 7*24*60*60*1000  //7d expire for cookie

        });
       // sending welcome email before response
       const  mailOption={
        from: process.env.SENDER_EMAIL,
        to: email,
        subject:'Welcome to Google Travels',
        text:`Welcome to Google travels website. Your account has been created with email id; ${email}`

       }
       await transporter.sendMail(mailOption);





        return res.json({success:true});



    }
    catch(error){

        res.json({success:false, message: error.message})
    }
}

export const login= async(req, res)=>{
    const {email, password}= req.body;

    if(!email || !password)
    {
        return res.json({success:false, message:'Email and password are required'})
    }
    try {
        const user= await userModel.findOne({email});
        if(!user) {
            return res.json({success:false,message:'Invalid email'});


        }

        const isMatch = await bcrypt.compare(password,user.password);   //checking is password correct
        if(!isMatch)
        {
            return res.json({success:false,message:'Invalid password'});
         }

          //generating token for authentication
        const token = jwt.sign({id:user._id},process.env.JWT_SECERT,{expiresIn:'7d'});

        //sending token to user in cookie form
        res.cookie('token',token, {
            httpOnly:true,
            secure: process.env.NODE_ENV==='production',
            sameSite: process.env.NODE_ENV==='production'?'none':'strict',
            maxAge: 7*24*60*60*1000  //7d expire for cookie

        });

        return res.json({success:true});




    }
    catch(error){
        return res.json({success:false,message:error.message});
    }
}

export const logout = async (req,res)=>{

    try {

        // just remove token from cookie after which it will not get authenticate
        res.clearCookie('token', {
            httpOnly:true,
            secure: process.env.NODE_ENV==='production',
            sameSite: process.env.NODE_ENV==='production'?'none':'strict',
            maxAge: 7*24*60*60*1000  //7d expire for cookie

        });
        return res.json({sucess:true,message:'Logged Out'});
        
        
    } catch (error) {
        return res.json({success:false,message:error.message});
        
    }
}

export const sendVerifyOtp= async (req,res) => {
    try {
        const {userId}= req.body;
     
       
       

        const user = await userModel.findById(userId);
       

        if(user.isAccountVerified)
        {
            return res.json({success:false, message:"Account already Verfied"});
        }
        const otp=String(Math.floor(100000+Math.random()*900000));  //generate 6 digit otp random
        

        //puting verify otp in user model so that later we can verify it
        user.verifyOtp=otp;
        user.verifyOtpExpireAt =Date.now()+24*60*60*1000
        await user.save();
        
        //sending otp to user mail so that it can verify
        const mailOption={
        from: process.env.SENDER_EMAIL,
        to: user.email,
        subject:'Verify Otp for email verfication from Google Travels',
        text:`Your verification Otp is ; ${otp}`

        }
        await transporter.sendMail(mailOption);

        res.json({success:true,message:'Verification OTP sent to your Email'});
     
    } catch (error) {
        res.json({success:false,message:error.message});
        
    }
}

export const verifyEmail = async (req, res) => {
    const {userId,otp} = req.body;   // we will get userid from token from middleware

    if(!userId || !otp)
    {
        return res.json({success:false, message:"Missing Details"});
    }
    try {
        const user = await userModel.findById(userId);

        if(!user)
        {
            return res.json({success:false, message:"User Not Found"});
        }

        // verify OTP
        if(user.verifyOtp === '' || user.verifyOtp!=otp)
        { 
            return res.json({success:false, message:"Invalid OTP"});

        }
        //Verify expiry of OTP
        if(user.verifyOtpExpireAt < Date.now())
        {
            return res.json({success:false, message:"Sorry OTP Expired"});
        }
        //mark accountverify as true
        user.isAccountVerified=true;

        user.verifyOtp='';
        user.verifyOtpExpireAt=0;

        await user.save();
        return res.json({success:true, message:"Email Verified successful"});
        
    } 
    catch (error) {
        return res.json({success:false, message:error.message});
        
    }
    
}
export const isAuthenticated = async (req,res) => {
    try {
        return res.json({success:true});
        
    } catch (error) {

         return res.json({success:false, message:error.message});
    }
    
}

export const sendResetOtp = async (req, res) => {
    const {email} = req.body;

    if(!email)
    {
        
        return res.json({success:false, message:'Email is required Sir/Mam'});
    }

    try {

        const user = await userModel.findOne({email});
         if(!user)
         {

                 return res.json({success:false, message:'User not Found please register first '});
         }

         //generate otp for reset pass
         const otp=String(Math.floor(100000+Math.random()*900000)); 
        //puting reset otp in user model so that later we can verify it
        user.resetOtp=otp;
        user.resetOtpExpireAt =Date.now()+24*60*60*1000
        await user.save();
        
        //sending otp to user mail so that it can verify
        const mailOption={
        from: process.env.SENDER_EMAIL,
        to: user.email,
        subject:'Password Reseting OTP',
        text:`Your Otp for reseting your password for email;${email} is ; ${otp} Use this Otp to proceed with reseting of password`

        }
        await transporter.sendMail(mailOption);

        res.json({success:true,message:' OTP sent to your Email'});

        
    } catch (error) {
        
          return res.json({success:false, message:error.message});
    }  
    
}
export const resetPassword= async (req, res) => {
   const  {email, otp, newPassword} = req.body;

   if(!email|| !otp || !newPassword)
   {
    return res.json({success:false, message:'Mising details'});
   }
   try {

    const user = await userModel.findOne({email});
    if(!user)
    {
        return res.json({success:false, message:'User not found'});
    }
    if(user.resetOtp ==="" || user.resetOtp!=otp)
    {
        return res.json({success:false, message:'invalid otp '});
    }
    if(user.resetOtpExpireAt< Date.now())
    {
        return res.json({success:false, message:'OTP expired please generate otp again'});
    }

    //otp is correct
    const hashedPassword= await bcrypt.hash(newPassword,10);

    user.password = hashedPassword;
    user.resetOtp="";
    user.resetOtpExpireAt=0;

    await user.save();

    return res.json({success:true, message:'Password reset Successfully'});
    
   } catch (error) {
    return res.json({success:false, message:error.message});
   }


    
}