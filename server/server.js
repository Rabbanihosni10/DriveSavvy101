import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import connectDB from './config/mongodb.js';
import authRouter from './routes/authRoutes.js';

// import { connect } from 'mongoose';
// import connectDB from './config/mongodb';
// import connectDB from './config/mongodb';

const app= express();
const PORT=process.env.PORT || 1205;
connectDB();
// connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(cors({credentials:true}));

//API Endpoints
app.get('/',(req,res)=>{
    res.send('API Working');
})
app.use('/api/auth',authRouter);

app.listen(PORT,()=>{
    console.log(`Server is running on PORT: ${PORT}`);
})