import {dotenv} from ("dotenv")
dotenv.config()

const express = require("express");
const cookieParser = require("cookie-parser");

const indexRouter = require("./routes/index");
const authRouter = require("./routes/auth");

const PORT = 8080;

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use("/", indexRouter);
app.use("/auth", authRouter);

app.listen(PORT, function () {
  console.log(`🚀 Listening on port ${PORT}`);
});

const mongoose = require("mongoose")
mongoose 
  .connect(process.env.MONGO_URI, {
    useNewUrlParser : true,
    useUnifiedTopology : true
  })
  .then(()=>{
    console.log("MongoDB connection is established successfully!")
  })

let sendRequest = document.querySelector("#fetch")
  sendRequest.addEventListener('click',async (e)=>{
    e.preventDefault()
    let data = await fetch('https://amaaq.github.io/authAPI/auth/signin',{
        method: "POST", // *GET, POST, PUT, DELETE, etc.
        mode: "cors", // no-cors, *cors, same-origin
        cache: "no-cache", // *default, no-cache, reload, force-cache, only-if-cached
        credentials: "same-origin", // include, *same-origin, omit
        headers: {
          "Content-Type": "application/json",
          // 'Content-Type': 'application/x-www-form-urlencoded',
        },
        redirect: "follow", // manual, *follow, error
        referrerPolicy: "no-referrer", // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
        body: JSON.stringify({
            email : "maaqoul.adil@gmail.com",
            password : "123456789"
        }), // body data type must match "Content-Type" header
      });
      let response = data.json()
      console.log(response)
    })