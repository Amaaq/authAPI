var express = require("express");
var router = express.Router();
const User = require('../models/user');
const {hash,compare}= require("bcryptjs")
const {verify} = require("jsonwebtoken")
const { protected } = require("../utils/protected");
const {createAccessToken,
    createRefreshToken,
    sendAccessToken,
    sendRefreshToken,
    createEmailVerifyToken,
    createPasswordResetToken 
} = require("../utils/tokens")

const {
  transporter,
  createPasswordResetUrl,
  passwordResetTemplate,
  passwordResetConfirmationTemplate,
} = require("../utils/email");
router.get('/', async (req, res) => {
	res.send('Hello Express!! 👋, this is Auth end point')
})

router.post("/signup",async (req,res)=>{
    try{
        const {email,password} = req.body;
        const user = await User.findOne({email: email});
        if(user)
            return res.status(500).json({
                message : "User already exists! Try logging in.",
                type : "warning"
            });
        const passwordHash = await hash(password,10);
        const newUser = new User({
            email: email,
            password: passwordHash
        })
        await newUser.save();
        res.status(200).json({
            message : "User created successfully!",
            type : "success"
        });
    } catch(error){
        res.status(500).json({
            message : "Error creating user!",
            type : "error",
            error
        });
    }
})
router.post("/signin",async (req,res)=>{
    try{
        const {email,password} = req.body;
        const user = await User.findOne({email: email});
        if(!user)
            return res.status(500).json({
                message : "User doesn't exist",
                type : "error"
            });
        const isMatch = await compare(password,user.password);
        if(!isMatch)
            return res.status(500).json({
                message : "Password is incorrect!",
                type : "error"
            });
        const accessToken = createAccessToken(user._id)
        const refreshToken = createRefreshToken(user._id)
        user.refreshtoken = refreshToken;
        await user.save();
        sendRefreshToken(res, refreshToken)
        sendAccessToken(req,res, accessToken)
    } catch(error){
        res.status(500).json({
            message : "Error signing in!",
            type : "error",
            error
        });
    }
})
router.post("/logout",(_req,res)=>{
    res.clearCookie("refreshtoken");
    return res.json({
        message: "Logged out successfully",
        type: "success"
    })
})
router.post("/refresh_token", async(req,res)=>{
    try {
        const {refreshtoken} = req.cookies;
        if(!refreshtoken)
            return res.status(500).json({
                message:"No refresh token!",
                type: "error"
            });
        let id;
        try {
            id = verify(refreshtoken,process.env.REFRESH_TOKEN_SECRET).id;
        }catch (error){
            return res.status(500).json({
                message: "Invalid refresh token!",
                type: "error"
            })
        }
        if (!id)
            return res.status(500).json({
                message: "Invalid refresh token! 🤔",
                type: "error",
            });
        // if the refresh token is valid, check if the user exists
        const user = await User.findById(id);
        // if the user doesn't exist, return error
        if (!user)
            return res.status(500).json({
                message: "User doesn't exist! 😢",
                type: "error",
            });
        // if the user exists, check if the refresh token is correct. return error if it is incorrect.
        if (user.refreshtoken !== refreshtoken)
            return res.status(500).json({
                message: "Invalid refresh token! 🤔",
                type: "error",
            });
        // if the refresh token is correct, create the new tokens
        const accessToken = createAccessToken(user._id);
        const refreshToken = createRefreshToken(user._id);
        // update the refresh token in the database
        user.refreshtoken = refreshToken;
        await user.save()
        // send the new tokes as response
        sendRefreshToken(res, refreshToken);
            return res.json({
            message: "Refreshed successfully! 🤗",
            type: "success",
            accessToken,
            });
    } catch (error) {
        res.status(500).json({
        type: "error",
        message: "Error refreshing token!",
        error,
        });
    }
})

router.get("/protected",protected,async (req, res) => {
  try {
    if (req.user)
      return res.json({
        message: "You are logged in! 🤗",
        type: "success",
        user: req.user,
      });
    return res.status(500).json({
      message: "You are not logged in! 😢",
      type: "error",
    });
  } catch (error) {
    res.status(500).json({
      type: "error",
      message: "Error getting protected route!",
      error,
    });
  }
});

// send password reset email
router.post("/send-password-reset-email", async (req, res) => {
  try {
    // get the user from the request body
    const { email } = req.body;
    // find the user by email
    const user = await User.findOne({ email });
    // if the user doesn't exist, return error
    if (!user)
      return res.status(500).json({
        message: "User doesn't exist! 😢",
        type: "error",
      });
    // create a password reset token
    let {_id ,password}= user
    const token = createPasswordResetToken({ _id, email, password });
    // create the password reset url
    const url = createPasswordResetUrl(user._id, token);
    // send the email
    const mailOptions = passwordResetTemplate(user, url);
    transporter.sendMail(mailOptions, (err, info) => {
      if (err)
        return res.status(500).json({
          message: "Error sending email! 😢",
          type: "error",
        });
      return res.json({
        message: "Password reset link has been sent to your email! 📧",
        type: "success",
      });
    });
  } catch (error) {
    res.status(500).json({
      type: "error",
      message: "Error sending!"+token,
      error,
    });
  }
});
router.post("/reset-password/:id/:token", async (req, res) => {
    try {
      // get the user details from the url
      const { id, token } = req.params;
      // get the new password the request body
      const { newPassword } = req.body;
      // find the user by id
      const user = await User.findById(id);
      // if the user doesn't exist, return error
      if (!user)
        return res.status(500).json({
          message: "User doesn't exist! 😢",
          type: "error",
        });
      // verify if the token is valid
      const isValid = verify(token, user.password);
      // if the password reset token is invalid, return error
      if (!isValid)
        return res.status(500).json({
          message: "Invalid token! 😢",
          type: "error",
        });
      // set the user's password to the new password
      user.password = await hash(newPassword, 10);
      // save the user
      await user.save();
      // send the email
      const mailOptions = passwordResetConfirmationTemplate(user);
      transporter.sendMail(mailOptions, (err, info) => {
        if (err)
          return res.status(500).json({
            message: "Error sending email! 😢",
            type: "error",
          });
        return res.json({
          message: "Email sent! 📧",
          type: "success",
        });
      });
    } catch (error) {
      res.status(500).json({
        type: "error",
        message: "Error sending email!",
        error,
      });
    }
  });

module.exports = router;
