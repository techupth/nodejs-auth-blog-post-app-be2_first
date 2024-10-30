import { Router } from "express";
import { db } from "../utils/db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const authRouter = Router();

// 🐨 Todo: Exercise #1
// ให้สร้าง API เพื่อเอาไว้ Register ตัว User แล้วเก็บข้อมูลไว้ใน Database ตามตารางที่ออกแบบไว้

authRouter.post("/register", async (req, res) => {
  const collection = db.collection("users");
  const { username, password, firstName, lastName } = req.body;
  const user = { username, password, firstName, lastName };

  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(user.password, salt);

  await collection.insertOne(user);

  //   console.log(user);

  return res.json({
    message: "User has been created successfully",
  });
});

// 🐨 Todo: Exercise #3
// ให้สร้าง API เพื่อเอาไว้ Login ตัว User ตามตารางที่ออกแบบไว้

authRouter.post("/login", async (req, res) => {
  const user = await db.collection("users").findOne({
    username: req.body.username,
  });

  if (!user) {
    return res.status(404).json({ message: "user not found" });
  }

  // console.log(user.body);

  const isPassword = await bcrypt.compare(req.body.password, user.password);

  if (!isPassword) {
    return res.status(401).json({
      message: "Invalid username or password",
    });
  }

  const token = jwt.sign(
    {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
    },
    process.env.SECRET_KEY,
    {
      expiresIn: "900000",
    }
  );

  return res.status(200).json({
    message: "login successfully",
    token,
  });
});

export default authRouter;
