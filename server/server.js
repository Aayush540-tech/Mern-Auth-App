import express from "express";
import cors from "cors"
import 'dotenv/config';
import cookieParser from "cookie-parser";
import connectDB from "./config/mongoDb.js";
import { authRouter } from "./Routes/auth.route.js";

const app= express();
const port= process.env.PORT || 4000
connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(cors({credentials : true}));


//API ENDPOINTS
app.get('/', (req,res)=> res.send("API WORKING FINE NOW"))
app.use('/api/auth',authRouter)

app.listen(port,()=> console.log(`server started at PORT ${port}...`));
