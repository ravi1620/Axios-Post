const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());  // Add JSON body parser middleware
app.use(express.urlencoded()); // Add URL-encoded body parser middleware
app.use("/uploads", express.static("uploads"));

let authorize = (req, res, next) => {
  console.log("Inside authorize middleware");
  console.log("Authorization Header:", req.headers['authorization']);  // Corrected way to access header
  next();
};

app.use(authorize);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads");
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, `${Date.now()}_${file.originalname}`);
  },
});

const upload = multer({ storage: storage });

let userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: String,
  password: String,
  mobile: String,
  profilePic: String,
});

let User = new mongoose.model("user", userSchema);

app.post("/validateToken", upload.none(), async (req, res) => {
  console.log("Request Body:", req.body);  // Check what is in the request body
  if (!req.body.token) {
    return res.status(400).json({ status: "Failed", msg: "Token is missing" });
  }

  try {
    let decryptedCred = jwt.verify(req.body.token, "abacabac");
    let userDetails = await User.find().and({ email: decryptedCred.email });

    if (userDetails.length > 0) {
      if (userDetails[0].password === decryptedCred.password) {
        let loginDetails = {
          firstName: userDetails[0].firstName,
          lastName: userDetails[0].lastName,
          email: userDetails[0].email,
          mobile: userDetails[0].mobile,
          profilePic: userDetails[0].profilePic,
        };

        return res.json({ status: "Success", data: loginDetails });
      } else {
        return res.json({ status: "Failed", msg: "Invalid Password" });
      }
    } else {
      return res.json({ status: "Failed", msg: "User does not exist" });
    }
  } catch (error) {
    console.error("JWT Verification Error:", error);
    return res.status(400).json({ status: "Failed", msg: "Invalid Token", error });
  }
});

app.post("/Login", upload.none(), async (req, res) => {
  console.log("Login Request Body:", req.body);
  let userDetails = await User.find().and({ email: req.body.email });

  if (userDetails.length > 0) {
    let ispasswordValid = await bcrypt.compare(req.body.password, userDetails[0].password);

    if (ispasswordValid) {
      let encryptedCred = jwt.sign({ email: req.body.email, password: req.body.password }, "abacabac");
      let loginDetails = {
        firstName: userDetails[0].firstName,
        lastName: userDetails[0].lastName,
        email: userDetails[0].email,
        mobile: userDetails[0].mobile,
        profilePic: userDetails[0].profilePic,
        token: encryptedCred,
      };

      return res.json({ status: "Success", data: loginDetails });
    } else {
      return res.json({ status: "Failed", msg: "Invalid Password" });
    }
  } else {
    return res.json({ status: "Failed", msg: "User does not exist" });
  }
});

app.post("/Signup", upload.single("profilePic"), async (req, res) => {
  console.log("Signup Request Body:", req.body);
  console.log("Uploaded File:", req.file);

  let hashedPassword = await bcrypt.hash(req.body.password, 10);

  try {
    let user1 = new User({
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      email: req.body.email,
      password: hashedPassword,
      mobile: req.body.mobile,
      profilePic: req.file ? req.file.path : null,
    });

    await User.insertMany([user1]);
    return res.json({ status: "Success", msg: "Successfully created User" });
  } catch (error) {
    return res.json({ status: "Failed", msg: "Unable to create User", error });
  }
});

app.patch("/update", upload.single('profilePic'), async (req, res) => {
  console.log("Update Request Body:", req.body);
  try {
    if (req.body.firstName && req.body.firstName.trim().length > 0) {
      await User.updateMany({ email: req.body.email }, { firstName: req.body.firstName });
    }

    if (req.body.lastName && req.body.lastName.trim().length > 0) {
      await User.updateMany({ email: req.body.email }, { lastName: req.body.lastName });
    }

    if (req.body.password && req.body.password.length > 0) {
      await User.updateMany({ email: req.body.email }, { password: req.body.password });
    }

    if (req.body.mobile && req.body.mobile.trim().length > 0) {
      await User.updateMany({ email: req.body.email }, { mobile: req.body.mobile });
    }

    if (req.file) {
      await User.updateMany({ email: req.body.email }, { profilePic: req.file.path });
    }

    return res.json({ status: "Success", msg: "Profile updated successfully" });
  } catch (error) {
    return res.json({ status: "Failed", msg: "Can't update profile", error });
  }
});

app.delete("/deleteProfile", async (req, res) => {
  let delResult = await User.deleteMany({ email: req.query.email });
  console.log("Delete Result:", delResult);
  return res.json({ status: "Success", msg: "Successfully deleted the account" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Listening to Port ${PORT}`);
});

const connectToDB = async () => {
  try {
    await mongoose.connect(process.env.mdburl);
    console.log("Successfully connected to DB");
  } catch (error) {
    console.log("Failed to connect to database", error);
  }
};

connectToDB();
