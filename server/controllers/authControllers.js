import User from '../models/user.js'; // Import the User model
import bcrypt from 'bcryptjs'; // Import bcrypt for password hashing
import speakeasy from 'speakeasy'; 
import qrCode from 'qrcode';
import jwt from "jsonwebtoken";

export const register = async (req, res) => {
    const { username, email, password } = req.body;

    // Validate request body
    if (!username || !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters long" });
    }
    const emailRegex = /.+\@.+\..+/; // Simple email validation
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: "Invalid email format" });
    }

    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: "User already exists" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            isMfaActive: false,
            twoFactorSecret: null,
        });

        // Save the user to the database
        await newUser.save();

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ error: "Error registering user", error: error.message });
    }
}
export const login = async (req, res) => {
    res.status(200).json({
        message: "Logged in successfully",
        username: req.username, // Pass the user object to the client
        isMfaActive: req.user.isMfaActive, // Pass the user's MFA status to the client  
    })
}
export const authStatus = async (req, res) => {
    if (req.user) {  
        res.status(200).json({
            message: "Authenticated successfully",
            username: req.username, // Pass the user object to the client
            isMfaActive: req.user.isMfaActive, // Pass the user's MFA status to the client  
        })
    } else {
        res.status(401).json({ message: "Not authenticated" }); 
        
    }
}
export const logout = async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ message: "Unauthorized user" });
    }

    req.logout((err) => {
        if (err) {
            return res.status(400).json({ message: "Error logging out user" });
        }
        return res.status(200).json({ message: "User logged out successfully" });
    });
}
export const setup2FA = async (req, res) => {
    const user = req.user;
    const secret = speakeasy.generateSecret();
    user.twoFactorSecret = secret.base32;
    user.isMfaActive = true;

    try {
        // Save the updated user with the new 2FA secret
        await user.save();

        const url = speakeasy.otpauthURL({
            secret: secret.base32,
            label: `${req.user.username}`,
            issuer: "www.dispeshmalvia.com",
            encoding: "base32"
        });

        const qrImageUrl = await qrCode.toDataURL(url);
        res.status(200).json({ message: "2FA setup successful", qrImageUrl, secret: secret.base32 });
    } catch (error) {
        res.status(500).json({ error: "Error setting up 2FA", error: error.message });
    }
}
export const verity2FA = async (req, res) => {
    const user = req.user;
    const { otp } = req.body;

    if (!user.isMfaActive) {
        return res.status(401).json({ message: "2FA is not enabled for this user" });
    }

    const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: "base32",
        token: otp
    });

    if (verified) {
        const jwtToken = jwt.sign(
            {username: user.username},
            process.env.JWT_SECRET,
            { expiresIn: "1h" }     
        )
        res.status(200).json({ message: "2FA verification successful", jwtToken });
    }else{
        return res.status(401).json({ message: "Invalid 2FA code" });

    }
}
export const reset2FA = async (req, res) => {
    try {
        const user = req.user;
        user.twoFactorSecret = "";
        user.isMfaActive = false;   
        await user.save();
        res.status(200).json({ message: "2FA reset successful"});
    } catch (error) {
        res.status(500).json({ error: "Error resetting 2FA", error: error.message });
    }
}
