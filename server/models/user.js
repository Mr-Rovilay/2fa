import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        match: /.+\@.+\..+/ // Simple email validation
    },
    password: {
        type: String,
        required: true,
    },
    isMfaActive: {
        type: Boolean,
        required: false,
    },
    twoFactorSecret: {
        type: String,
        required: false,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

// Export the User model
const User =  mongoose.model('User', userSchema);
export default User;
