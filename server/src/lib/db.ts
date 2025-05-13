import mongoose from "mongoose";
import dotenv from 'dotenv'

dotenv.config()

const MONGO_URL = process.env.MONGO_URL!;

export const connectToDb = () => {
   
 mongoose.connect(MONGO_URL);
    mongoose.connection.on("connected", () => {
        console.log("Connected to MongoDB");
    });
    mongoose.connection.on("error", (err) => {
        console.error("Error connecting to MongoDB", err);
    });
}