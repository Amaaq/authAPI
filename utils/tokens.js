const {sign} = require("jsonwebtoken")
const createAccessToken = (id)=>{
    return sign({id},process.env.ACCESS_TOKEN_SECRET,{
        expiresIn:15*60
    })
}
const createRefreshToken = (id)=>{
    return sign({id},process.env.REFRESH_TOKEN_SECRET,{
        expiresIn:"90d"
    })
}
const sendAccessToken = (_req,res,accesstoken)=>{
    res.json({
        accesstoken,
        message:"Sign in successful",
        type: "success",
    })
}
const sendRefreshToken = (res,refreshtoken)=>{
    res.cookie("refreshtoken",refreshtoken,{
        httpOnly:true
    })
}
const createEmailVerifyToken = (id)=>{
    return sign({id},process.env.VERIFY_TOKEN_SECRET,{
        expiresIn:15*60
    })
}
const createPasswordResetToken = ({ _id, email, password }) => {
    const secret = password;
    return sign({ id: _id, email }, secret, {
      expiresIn: 15 * 60, // 15 minutes
    });
  };
module.exports = {
    createAccessToken,
    createRefreshToken,
    sendAccessToken,
    sendRefreshToken,
    createEmailVerifyToken,
    createPasswordResetToken
}