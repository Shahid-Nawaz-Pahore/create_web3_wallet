// src/auth/schemas/user.schema.ts
import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class User extends Document {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ required: true })
  encryptedPrivateKey: string;   

  @Prop({required: true})
  walletAddress: string;

  @Prop() // Field to store the generated OTP
  otp?: string;

  @Prop() // Field to store OTP expiration time
  otpExpiresAt?: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
