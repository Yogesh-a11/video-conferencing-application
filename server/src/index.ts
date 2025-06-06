import express from  'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import { connectToDb } from './lib/db'
import userRoutes from './routes/authRoutes'
import dotenv from 'dotenv'

dotenv.config()

const port = process.env.PORT || 3000
const app = express()
app.use(express.json())

app.use(cookieParser())
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true
}))

app.use('/api/v1/user', userRoutes)
console.log('userRoutes type:', typeof userRoutes);

connectToDb()

app.listen(port, () => {
    console.log(`Server running on port ${port}`)
})
