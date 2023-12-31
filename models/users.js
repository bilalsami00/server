import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
 
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


userSchema.pre("save", async function(next){

    // if the old user changes his name? then y hash password over and over ??? that is y ↓
    if(!this.isModified("password")) return next();

    // ↓ this is to "hash" i.e encrypt the password
    const salt = await bcrypt.genSalt(10); // salt is basically a random string generated by "genSalt" 
    this.password = await bcrypt.hash(this.password, salt);
    next();
});


userSchema.methods.getJWTToken = function () {
     return jwt.sign({ _id: this._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_COOKIE_EXPIRE*24*60*60*1000,
    });
};


userSchema.methods.comparePassword = async function (password){
    return await bcrypt.compare(password, this.password)
}

export const User = mongoose.model("User", userSchema);
