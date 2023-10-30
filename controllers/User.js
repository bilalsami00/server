import { User } from "../models/users.js";
import { sendMail } from "../utils/sendMail.js";
import { sendToken } from "../utils/sendToken.js";

export const register = async (req, res) => {
 try {
    const {name,email,password} = req.body 
   //  const {avatar} = req.files 
   
    let user = await User.findOne({ email})
    if (user) {
        return res 
        .status(400)
        .json({success:false, message: "User already exist"})
    }

    const otp = Math.floor(Math.random()* 100000)
    user = await User.create(
      {name,
       email,
       password,
       avatar:{
         public_id:"",
         url:"",
       },
       otp,
       otp_expiry: new Date(Date.now() + process.env.OTP_EXPIRE * 60 *1000)})

    await sendMail(email, "Verify your account", `Your OTP is ${otp}`)
    
    sendToken(
      res, 
      user, 
      201, 
      "OTP sent to your email, please verify your account"
      )

 } catch (error) {
    res.status(500).json({success:false, message: error.message})
    
 }   
}

// acc to comment on line n.o 49 we will only be able to "verify" if we've already logged in otherwise it wont
export const verify = async (req, res) =>{
   try {
   
      const otp = Number(req.body.otp)

      // from middleware's auth.js user._id >> 
      // as the "user" login              ↓ we will get all the information of the said user in "req.user" 
      const user = await User.findById(req.user._id)

      if (user.otp !== otp || user.otp_expiry < Date.now()) {
         return res
           .status(400)
           .json({ success: false, message: "Invalid OTP or has been expired" });
       }
       

      user.verified = true
      user.otp = null
      user.otp_expiry = null
      
      await user.save()

      sendToken(res, user, 200, "Account Verified")


   } catch (error) {
      
      res.status(500).json({success:false, message: error.message})
      
   }
}


//login method
export const login = async (req, res) => {
   try {
      const {email,password} = req.body 
     
      const user = await User.findOne({ email}).select("+password");

      if(!email || !password){
         return res
         .status(400)
         .json({success:false, message:"Please enter all fields"})
      }

      if (!user) {
          return res 
          .status(400)
          .json({success:false, message: "Invalid Email or Password"})
      }
  
      const isMatched = await user.comparePassword(password)

      if(!isMatched){
         return res
         .status(400)
         .json({success:false, message:"Invalid Email or Password"})
      }
      
      sendToken(
        res, 
        user, 
        200, 
        "Login Successful"
        )
  
   } catch (error) {
      res.status(500).json({success:false, message: error.message})
   }   
  }

// logout method
  export const logout = async (req, res) => {
   try {
      res.status(200).cookie("token", null,{
         expire: new Date(Date.now())
      }).json({success:true, message: "logged Out Successful"})
   } catch (error) {
      res.status(500).json({success:false, message: error.message})
   }   
  }