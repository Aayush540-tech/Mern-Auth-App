import jwt from 'jsonwebtoken';

const userAuth = async (req,res,next) => {
    const {token} = req.cookies;
    
    if(!token){
        return res.json({success:false, message:"Not Authorized Login Again"});
    }

    try {
        const tokenDecode=jwt.verify(token, process.env.JWT_SECERT);
      
        if(tokenDecode.id){
            req.body= { userId:tokenDecode.id,...req.body};
            
        }
        
        else
        {
            return res.json({success:false, message:"Not Authorized Login Again"});
          
        }
        

        
        next();
     
        
    } catch (error) {
        return res.json({success:false, message:error.message});
        
    }
    
}

export default userAuth;