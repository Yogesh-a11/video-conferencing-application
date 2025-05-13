import User from "../models/userModel";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Request, Response } from "express";
import { generateAccessToken, generateRefreshToken } from "../lib/jwt";

export const register = async (req: Request, res: Response): Promise<void> => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            res.status(400).json({ message: "Please provide all required fields" });
            return;
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            res.status(400).json({ message: "User already exists" });
            return;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
       const user = await User.create({ name, email, password: hashedPassword });
        const accessToken = generateAccessToken(user._id as string);
        const refreshToken = generateRefreshToken(user._id as string);  
        
        user.refreshToken = refreshToken;
        await user.save();
        

        const userResponse = {
            _id: user._id,
            name: user.name,
            email: user.email,
          };
 

        res
        .cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        })
        .cookie("token", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 60 * 60 * 1000, // 1 hour
        })
        .status(200)
        .json({ message: "Logged in successfully", user: userResponse });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
};

export const login = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            res.status(400).json({ message: "Please provide email and password" });
            return;
        }

        const user = await User.findOne({ email });
        if (!user) {
            res.status(401).json({ message: "Invalid credentials" });
            return;
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
                res.status(401).json({ message: "Invalid credentials" });
                return;
        }

        const accessToken = generateAccessToken(user._id as string);
        const refreshToken = generateRefreshToken(user._id as string);
        
        user.refreshToken = refreshToken;
        await user.save();
        
        const userResponse = {
            _id: user._id,
            name: user.name,
            email: user.email,
        };
        

        res
        .cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        })
        .cookie("token", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 60 * 60 * 1000, // 1 hour
        })
        .status(200)
        .json({ message: "Logged in successfully", user: userResponse });
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Failed to log in user', error });
    }

}

export const refreshAccessToken = async (req: Request, res: Response) => {
    const token = req.cookies.refreshToken;
    if (!token) {
        res.status(401).json({ message: 'No refresh token' })  
        return ;
    }
  
    try {
      const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET!) as { id: string };
        if (!decoded.id) {
            res.status(401).json({ message: 'Invalid refresh token' });
            return ;
        }
      const user = await User.findById(decoded.id as string);
  
      if (!user || user.refreshToken !== token) {
        res.status(403).json({ message: 'Invalid refresh token' });
        return;
      }
  
      const newAccessToken = generateAccessToken(user._id as string);
  
      res
        .cookie('token', newAccessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 60 * 60 * 1000, // 1 hour
        })
        .status(200)
        .json({ message: 'Access token refreshed' });
  
        res.status(200).json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
}; 

export const logout = (req: Request, res: Response) => {
    try {
        res.clearCookie("token").status(200).json({ message: "Logged out" });
    } catch (error) {
        res.status(500).json({ message: "Failed to log out", error });
    }
};