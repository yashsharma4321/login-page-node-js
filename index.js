import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";

import bcrypt from "bcrypt";
const app = express();

// Middleware setup
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// MongoDB connection
mongoose.connect("mongodb://localhost:27017/", {
    dbName: "backend",
})
    .then(() => console.log("MongoDB is connected"))
    .catch((e) => console.log("Connection failed", e));

// User schema and model
const UserSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
});

const User = mongoose.model("User", UserSchema);

// Setting up view engine
app.set("view engine", "ejs");

// Authentication middleware
const isauthenticate = async (req, res, next) => {
    const { token } = req.cookies;
    if (token) {
        try {
            const decoded = jwt.verify(token, "fhfyddugkhkhhih");
            req.user = await User.findById(decoded._id);
            next();
        } catch (err) {
            res.clearCookie("token");
            res.redirect('/login');
        }
    } else {
        res.render('login');
    }
};

// Routes
app.get('/', isauthenticate, (req, res) => {
    res.render('logout');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    let user = await User.findOne({ email });
    if (!user) {
        return res.redirect('/register');
    }


    const ismatch = await bcrypt.compare(password,user.password);
    if (!ismatch) {
        return res.redirect('/login');
    }

    const token = jwt.sign({ _id: user._id }, "fhfyddugkhkhhih");
    res.cookie('token', token, {
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000),
    });

    res.redirect('/');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    let user = await User.findOne({ email });
    if (user) {
        return res.redirect('/login');
    }
    const hashedPassword = await bcrypt.hash(password,10)


    user = await User.create({
        name,
        email,
        password : hashedPassword,
    });

    const token = jwt.sign({ _id: user._id }, "fhfyddugkhkhhih");
    res.cookie('token', token, {
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000),
    });

    res.redirect('/');
});

app.get('/logout', (req, res) => {
    res.cookie('token', null, {
        httpOnly: true,
        expires: new Date(Date.now()),
    });
    res.redirect('/login');
});

// Starting the server
app.listen(5000, () => {
    console.log("Server is working on port 5000");
});
