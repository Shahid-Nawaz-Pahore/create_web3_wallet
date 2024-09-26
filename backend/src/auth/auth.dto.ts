import { IsEmail, IsString, IsNotEmpty } from 'class-validator';

export class RegisterDto {
    @IsEmail({}, { message: 'Email must be a valid email address' })
    email: string;

    @IsString()
    @IsNotEmpty({ message: 'Password is required' })
    password: string;
}

export class LoginDto {
    @IsEmail({}, { message: 'Email must be a valid email address' })
    email: string;

    @IsString()
    @IsNotEmpty({ message: 'Password is required' })
    password: string;
}

export class SendOtpDto {
    @IsEmail({}, { message: 'Email must be a valid email address' })
    email: string;
}

export class VerifyOtpDto {
    @IsString()
    @IsNotEmpty({ message: 'OTP is required' })
    otp: string;
}
