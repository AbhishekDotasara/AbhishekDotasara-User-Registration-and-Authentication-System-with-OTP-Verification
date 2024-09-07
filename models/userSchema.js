const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const SECRET_KEY = "abcdefghijklmnop";

const userSchema = new mongoose.Schema({
    fname: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        validate(value) {
            if (!validator.isEmail(value)) {
                throw new Error("Not a valid Email");
            }
        }
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    tokens: [{
        token: {
            type: String,
            required: true,
        }
    }]
});

// Hash password before saving
userSchema.pre("save", async function(next) {
    if (this.isModified("password")) {
        this.password = await bcrypt.hash(this.password, 12);
    }
    next();
});

// Generate authentication token
userSchema.methods.generateAuthToken = async function() {
    try {
        let newToken = jwt.sign({ _id: this._id }, SECRET_KEY, {
            expiresIn: "1d"
        });

        this.tokens = this.tokens.concat({ token: newToken });
        await this.save();
        return newToken;
    } catch (error) {
        console.error(error);
        throw new Error("Token generation failed");
    }
}

// Create model
const User = mongoose.model("User", userSchema);

module.exports = User;
