import jwt, { SignOptions } from 'jsonwebtoken';
  import { IUser } from '../models/User';

const JWT_SECRET = process.env.JWT_SECRET || 'zedflip-fallback-secret-key-2025';
const JWT_EXPIRE = process.env.JWT_EXPIRE || '7d';

interface TokenPayload {
  id: string;
  email: string;
  isAdmin: boolean;
}

export const generateToken = (user: IUser): string => {
  const payload: TokenPayload = {
    id: user._id.toString(),
    email: user.email,
    isAdmin: user.isAdmin,
  };

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRE,
  } as SignOptions);
};
export const verifyToken = (token: string): TokenPayload => {
  return jwt.verify(token, JWT_SECRET) as TokenPayload;
};

export const generateRefreshToken = (user: IUser): string => {
  return jwt.sign(
    { id: user._id.toString() },
    JWT_SECRET,
    { expiresIn: '30d' } as SignOptions  );
};

export default { generateToken, verifyToken, generateRefreshToken };
