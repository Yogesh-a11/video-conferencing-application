import { Router } from "express";
import { login, logout, refreshAccessToken, register } from "../controllers/authController";
import { protect } from "../middlewares/authMiddleware";

const router = Router();

router.post("/register", register);
router.post("/login", login);
router.get('/refresh', refreshAccessToken)
router.get('/logout', protect, logout)

export default router;