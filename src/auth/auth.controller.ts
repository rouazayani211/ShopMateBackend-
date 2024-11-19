import { Controller, Post, Body, Get, Put, Res, UseGuards, Query, Param, UnauthorizedException, NotFoundException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../user/dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { MailService } from '../mail/mail.service';
import { ResetPasswordDto } from 'src/user/dto/reset-password.dto';
import { UserService } from 'src/user/user.service';
import * as crypto from 'crypto';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly mailService: MailService,
    private readonly userService: UserService,
    private readonly authService: AuthService
  ) {}

  @Post('signup')
  async signup(@Body() createUserDto: CreateUserDto) {
    return this.authService.signup(createUserDto);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    const user = await this.authService.validateUser(loginDto.email, loginDto.password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
  
    const accessToken = await this.authService.login(user);
    return {
      access_token: accessToken.access_token,
      user: {
        _id: user._id,
        nom: user.nom,
        prenom: user.prenom,
        email: user.email,
        historiqueAchat: user.historiqueAchat,
        preferences: user.preferences,
      },
    };
  }

  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth() {}

  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  async googleAuthRedirect(@Query('code') code: string) {
    const user = await this.authService.googleLogin(code);
    return {
      message: 'User information from Google',
      user,
    };
  }

  // Endpoint to initiate the password reset process
  @Post('forgot-password')
  async forgotPassword(@Body('email') email: string): Promise<{ message: string }> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User with this email does not exist.');
    }

    const resetCode = Math.floor(100000 + Math.random() * 900000).toString(); // Generate a 6-digit numeric reset code
    await this.userService.saveResetToken(user._id.toString(), resetCode); // Save reset code and expiration

    await this.mailService.sendResetPasswordEmail(email, resetCode); // Send the reset code via email
    return { message: 'Password reset code has been sent to your email address.' };
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    const { resetToken, newPassword } = resetPasswordDto;

    if (!resetToken) {
      throw new UnauthorizedException('Reset token is missing.');
    }

    // Hash the reset token from the request
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    console.log(`Reset Token (incoming): ${resetToken}`);
    console.log(`Hashed Token (calculated): ${hashedToken}`);

    // Find the user by the hashed token
    const user = await this.userService.findByResetToken(hashedToken);

    if (!user || user.resetPasswordExpires < Date.now()) {
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    // Validate password format (optional)
    if (newPassword.length < 8 || !/[A-Z]/.test(newPassword) || !/\W/.test(newPassword)) {
      throw new UnauthorizedException(
        'Password must be at least 8 characters long, include one uppercase letter, and one special character.'
      );
    }

    // Update the user's password
    await this.userService.updatePassword(user._id.toString(), newPassword);

    return { message: 'Password updated successfully' };
  }

  @Get('verify-email')
  async verifyEmail(@Query('token') token: string, @Res() res: Response) {
    const user = await this.userService.findByVerificationToken(token);

    if (!user || user.emailVerificationExpires < Date.now()) {
      throw new UnauthorizedException('Invalid or expired verification token.');
    }

    user.emailVerified = true; // Mark email as verified
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    // Send a success template
    return res.send(`
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; text-align: center; border: 1px solid #ddd; border-radius: 10px;">
        <h2 style="color: #4CAF50;">Email Verified Successfully!</h2>
        <p style="color: #555;">Thank you for verifying your email. You can now log in to your account.</p>
        <a href="http://yourapp.com/login" style="background-color: #007bff; color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; font-size: 16px;">Go to Login</a>
      </div>
    `);
  }

  @Get('check-verification-status')
  async checkVerificationStatus(@Query('email') email: string) {
    const user = await this.userService.findByEmail(email);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return {
      emailVerified: user.emailVerified,
    };
  }

  // Update user profile information
  @Put('update-user/:id')
  async updateUser(
    @Param('id') id: string,
    @Body() updateData: { nom: string; prenom: string; email: string; password?: string }
  ) {
    return this.userService.updateUser(id, updateData);
  }
}