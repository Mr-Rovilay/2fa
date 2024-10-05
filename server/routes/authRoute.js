import express from 'express';
import passport from 'passport';
import { authStatus, login, logout, register, reset2FA, setup2FA, verity2FA } from '../controllers/authControllers.js';

const router = express.Router();


router.post("/register", register);
router.post("/login",passport.authenticate("local"), login);
router.get("/status", authStatus);
router.post("/logout", logout);

router.post("/2fa/setup", (req,res, next) => {
    if (req.isAuthenticated()) {
        return next()    
    } else{
        return res.status(401).json({ message: "Unauthorized user" });
    }
}, setup2FA);
router.post("/2fa/verify", (req,res, next) => {
    if (req.isAuthenticated()) {
        return next()    
    } else{
        return res.status(401).json({ message: "Unauthorized user" });
    }
}, verity2FA);
router.post("/2fa/reset", (req,res, next) => {
    if (req.isAuthenticated()) {
        return next()    
    } else{
        return res.status(401).json({ message: "Unauthorized user" });
    }
}, reset2FA);

export default router