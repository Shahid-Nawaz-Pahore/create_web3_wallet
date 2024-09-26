import { Request } from 'express';

declare global {
  namespace Express {
    interface Request {
      user?: any; // or use a more specific type based on your JWT payload
    }
  }
}
