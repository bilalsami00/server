import mongoose from "mongoose";
import jwt from "jsonwebtoken";
 
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
        minlength: [8, "Password must be 8 characters or more"],
        select: false,
    },
    avatar: {
        public_id: String,
        url: String,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    tasks: [
        {
            title: String,
            description: String,
            completed: Boolean,
            createdAt: Date,
        },
    ],
    verified: {
        type: Boolean,
        default: false,
    },
    otp: Number,
    otp_expiry: Date,
});

userSchema.methods.getJWTToken = function () {
     return jwt.sign({ _id: this._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_COOKIE_EXPIRE,
    });
};

export const User = mongoose.model("User", userSchema);
