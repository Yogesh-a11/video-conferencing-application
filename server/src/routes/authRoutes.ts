import { Router } from "express";
import { login, logout, refreshAccessToken, register } from "../controllers/authController";

const router = Router();

router.post("/register", register);
router.post("/login", login);
router.get('/refresh', refreshAccessToken)
router.get('/logout', logout)

export default router;