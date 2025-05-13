import mongoose, { Document, Model, Schema } from "mongoose";
import bcrypt from 'bcryptjs';

interface IUser {
  name: string;
  email: string;
  password: string;
  refreshToken: string | null;
}

interface IUserDocument extends IUser, Document {
  comparePassword(password: string): Promise<boolean>;
}

const userSchema = new Schema<IUserDocument>(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

     refreshToken: {
      type: String,
      default: null,
    },    

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    password: {
      type: String,
      required: true,
      minlength: 6,
    },
  },
  { timestamps: true }
);


userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});


userSchema.methods.comparePassword = async function (password: string): Promise<boolean> {
  return bcrypt.compare(password, this.password);
};

const User = mongoose.model<IUserDocument>('User', userSchema);

export default User;
