require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const User = require("./models/user");
const Order = require("./models/order");

const app = express();
app.use(express.json()); // To parse JSON bodies
const port = process.env.PORT;
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY || "your_jwt_secret_key_here";

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

if (process.env.NODE_ENV === "development") {
  const cors = require("cors");
  app.use(cors());
}

mongoose
  .connect(process.env.DB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Error connecting to MongoDB", err));

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

const sendVerificationEmail = async (email, verificationToken) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });

  const mailOptions = {
    from: "amazon.com",
    to: email,
    subject: "Email Verification",
    text: `Please click the following link to verify your email: http://${process.env.IP_ADDRESS}:${process.env.PORT}/verify/${verificationToken}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("Verification email sent successfully");
  } catch (error) {
    console.error("Error sending verification email:", error);
  }
};

// Register a new user
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered" });
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = new User({ name, email, password: hashedPassword });

    newUser.verificationToken = crypto.randomBytes(20).toString("hex");
    await newUser.save();
    sendVerificationEmail(newUser.email, newUser.verificationToken);
    res.status(201).json({
      message:
        "Registration successful. Please check your email for verification.",
    });
  } catch (error) {
    res.status(500).json({ message: "Registration failed",  error: error.message});
  }
});

// Email verification
app.get("/verify/:token", async (req, res) => {
  try {
    const token = req.params.token;
    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return res.status(404).json({ message: "Invalid verification token" });
    }
    user.verified = true;
    user.verificationToken = undefined;
    await user.save();
    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    res.status(500).json({ message: "Email Verification Failed" });
  }
});

const secretKey = process.env.SECRET_KEY;

// User login
app.post("/login", async (req, res) => {
  try {
      const { email, password } = req.body;

      // Find the user by email
      const user = await User.findOne({ email });
      if (!user) {
          return res.status(401).json({ message: "Invalid email or password." });
      }

      // Compare the provided password with the hashed password in the database
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
          return res.status(401).json({ message: "Invalid email or password." });
      }

      // Assuming the user is verified and the password matches
      // Generate a JWT token
      const token = jwt.sign({ userId: user._id }, JWT_SECRET_KEY, { expiresIn: '1h' });

      // Send the token to the client
      res.status(200).json({ message: "Login successful", token: token });
  } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ message: "Internal server error" });
  }
});

// Add a new address
app.post("/addresses", async (req, res) => {
  try {
    const { userId, address } = req.body;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    user.addresses.push(address);
    await user.save();
    res.status(200).json({ message: "Address added successfully" });
  } catch (error) {
    console.error("Error adding address:", error);
    res.status(500).json({ message: "An error occurred" });
  }
});


// Retrieve addresses for a user
app.get("/addresses/:userId", async (req, res) => {
  const userId = req.params.userId;
  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  res.status(200).json({ addresses: user.addresses });
});

// Create a new order
app.post("/orders", async (req, res) => {
  const { userId, cartItems, totalPrice, shippingAddress, paymentMethod } =
    req.body;
  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  const order = new Order({
    user: userId,
    products: cartItems,
    totalPrice,
    shippingAddress,
    paymentMethod,
  });
  await order.save();
  res.status(200).json({ message: "Order created successfully!" });
});

// Retrieve a user profile
app.get("/profile/:userId", async (req, res) => {
  const userId = req.params.userId;
  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  // Exclude sensitive information like password from the response
  const { password, ...userWithoutPassword } = user.toObject();
  res.status(200).json({ user: userWithoutPassword });
});

// Retrieve orders for a user
app.get("/orders/:userId", async (req, res) => {
  const userId = req.params.userId;
  const orders = await Order.find({ user: userId }).populate(
    "products.product"
  );
  if (orders.length === 0) {
    return res.status(404).json({ message: "No orders found for this user" });
  }
  res.status(200).json({ orders });
});
