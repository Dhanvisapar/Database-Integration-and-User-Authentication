const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.static("public"));

/* DATABASE */
mongoose.connect("mongodb://127.0.0.1:27017/task6");

/* MODELS */
const User = mongoose.model("User", {
  username: String,
  password: String
});

const Data = mongoose.model("Data", {
  value: String,
  userId: String
});

/* AUTH MIDDLEWARE */
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.sendStatus(401);

  try {
    req.user = jwt.verify(token, "secretkey");
    next();
  } catch {
    res.sendStatus(403);
  }
}

/* REGISTER */
app.post("/register", async (req, res) => {
  const hashed = await bcrypt.hash(req.body.password, 10);
  await User.create({ username: req.body.username, password: hashed });
  res.send("Registered");
});

/* LOGIN */
app.post("/login", async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (!user) return res.sendStatus(401);

  const valid = await bcrypt.compare(req.body.password, user.password);
  if (!valid) return res.sendStatus(401);

  const token = jwt.sign({ id: user._id }, "secretkey");
  res.json({ token });
});

/* PROTECTED API */
app.post("/data", auth, async (req, res) => {
  await Data.create({ value: req.body.value, userId: req.user.id });
  res.send("Data saved");
});

app.get("/data", auth, async (req, res) => {
  const data = await Data.find({ userId: req.user.id });
  res.json(data);
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
