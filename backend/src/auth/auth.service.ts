import { Injectable, HttpException, HttpStatus } from '@nestjs/common'; // Import HttpException and HttpStatus
import { ethers } from 'ethers';
import * as bcrypt from 'bcrypt';
import * as CryptoJS from 'crypto-js';
import * as speakeasy from 'speakeasy';
import * as nodemailer from 'nodemailer';
import { User } from './schema/user.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
    constructor(@InjectModel(
        User.name) private userModel: Model<User>,
        private jwtService: JwtService,
        private configService: ConfigService
    ) {
    }
  
  // Generate an Ethereum wallet connected to the Sepolia test network
  generateWallet() {
    // Create a provider for the Sepolia test network
    const provider = new ethers.providers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
    // Create a random wallet and connect it to the provider
    const wallet = ethers.Wallet.createRandom().connect(provider);
    return wallet;
  }

  // Register a user and encrypt the private key
  async register(email: string, password: string) {
    // Check if the password is provided
    if (!password) {
      throw new HttpException('Password is required', HttpStatus.BAD_REQUEST); // Throw an exception if no password
    }

    
    const wallet = this.generateWallet();
    const hashedPassword = await bcrypt.hash(password, 10);
    const encryptedPrivateKey = CryptoJS.AES.encrypt(wallet.privateKey, password).toString();
  
    const newUser = new this.userModel({
        email:email,
        password: hashedPassword,
        encryptedPrivateKey:encryptedPrivateKey,
        walletAddress: wallet.address,
      });
  
      await newUser.save();
  
    return {
        walletAddress: wallet.address,
        balance: await wallet.getBalance(),
        encryptedPrivateKey 
    };
  }

  async login(email: string, password: string) {
    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND); // User does not exist
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      throw new HttpException('Invalid password', HttpStatus.UNAUTHORIZED); // Incorrect password
    }

 
    const provider = new ethers.providers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
    const balance = await provider.getBalance(user.walletAddress); 
    const formattedBalance = ethers.utils.formatEther(balance); 


    const token = this.jwtService.sign(
      { email: user.email, walletAddress: user.walletAddress},
      {expiresIn:'1h'}
    );

 
    return {
      accessToken: token,
      walletAddress: user.walletAddress,
      balance: formattedBalance,
    };
  }
  // Send OTP for 2FA using nodemailer
  async sendOTP(email: string) {
    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    const otp = speakeasy.totp({
      secret: process.env.OTP_SECRET,
      encoding: 'base32',
      step: 300, // OTP valid for 5 minutes
    });

    const otpExpiresAt = new Date(); // Get current date and time
    otpExpiresAt.setMinutes(otpExpiresAt.getMinutes() + 5); // Set OTP expiration to 5 minutes from now

    // Update user with OTP and expiration time
    user.otp = otp;
    user.otpExpiresAt = otpExpiresAt;
    await user.save(); // Save the updated user document

    // Send OTP to email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const htmlMessage = `
      <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333;">
        <h2>Dear User,</h2>
        <p>Your OTP code for two-factor authentication is: <strong>${otp}</strong>. This code is valid for 5 minutes.</p>
        <p>Please use it to verify your identity.</p>
        <br />
        <p>Regards,</p>
        <p>OCTALOOP TECHNOLOGIES</p>
      </div>
    `;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code for Verification',
      html: htmlMessage,
    });

    return { message: 'OTP sent successfully' };
  }



  // Verify the OTP
async verifyOTP(otp: string): Promise<boolean> {
  // Find user by OTP (this assumes OTPs are unique within the expiration window)
  const user = await this.userModel.findOne({ otp });

  // If no user is found, or the OTP or expiration date is missing, return an error
  if (!user || !user.otp || !user.otpExpiresAt) {
    throw new HttpException('OTP not found or expired', HttpStatus.NOT_FOUND);
  }

  // Check if the OTP has expired
  const currentTime = new Date();
  if (currentTime > user.otpExpiresAt) {
    throw new HttpException('OTP has expired', HttpStatus.BAD_REQUEST);
  }

  // If OTP is valid, clear it and update the user's record in the database
  if (user.otp === otp) {
    user.otp = null;            // Clear the OTP after successful verification
    user.otpExpiresAt = null;    // Clear expiration time
    await user.save();           // Save the updated user record
    return true;                 // Return true if OTP verification is successful
  }

  return false;  // Return false if OTP does not match
}

}
