
import { IUser } from "../models/userModel";

declare global {
  namespace Express {
    interface Request {
      user?: IUser;  // Attach full user object after auth
    }
  }
}
