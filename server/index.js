import express from 'express';
import session from 'express-session';
import passport from 'passport';
import connectDB from "./db/db.js";
import dotenv  from 'dotenv';
import cors from 'cors';
import authRoute from './routes/authRoute.js';
import "./config/passportConfig.js"

const PORT = process.env.PORT || 5000;

dotenv.config() 
const app = express();

const corsOptions = {
    origin: '*', // Replace with your frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true,
};

app.use(cors(corsOptions));

  app.use(express.urlencoded({ extended: true }));
  app.use(express.json()); 
  app.use(session({
    secret: process.env.SESSION_SECRET || "secret", 
    resave: false,
    saveUninitialized: true,
    cookie: { 
        maxAge: 60000 * 60, // 10 minutes
        secure: false, // Set to true in production environment. Set to false for local development to avoid https issues.  // Change this to true in production environment
     }  // Change this to true in production environment
  }))

  app.use(passport.initialize());   
  app.use(passport.session());

  app.use("/api/auth", authRoute)


  connectDB().then(() => {
    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
    });

  }).catch(err => {
    console.error("Failed to connect to the database", err);
  });