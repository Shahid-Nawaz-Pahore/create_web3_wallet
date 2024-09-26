// src/auth/auth.controller.ts
import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiTags, ApiBody, ApiOperation } from '@nestjs/swagger';
import { RegisterDto, LoginDto, SendOtpDto, VerifyOtpDto } from './auth.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
@ApiTags('Auth') 
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new user and generate a wallet' })
  @ApiBody({ type: RegisterDto })
  async register(@Body() body:RegisterDto) {
    return this.authService.register(body.email, body.password);
  }


  @Post('login')
  @ApiOperation({ summary: 'Login with email and password and return wallet details' })
  @ApiBody({ type: LoginDto })
  async login(@Body() body: LoginDto) {
    return this.authService.login(body.email, body.password); 
  }



  @Post('send-otp')
  @ApiOperation({ summary: 'Send OTP for two-factor authentication' }) 
  @ApiBody({ type: SendOtpDto })
  async sendOTP(@Body() body: SendOtpDto) {
    return this.authService.sendOTP(body.email);
  }

  @Post('verify-otp')
  //@UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Verify the provided OTP' })
  @ApiBody({ type: VerifyOtpDto })
  async verifyOTP(@Body() body: VerifyOtpDto) {
    const isValid = await this.authService.verifyOTP(body.otp); 
    return { valid: isValid };
  }
}
