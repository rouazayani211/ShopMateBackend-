import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from '../user/shemas/user.schema';
import { UserService } from '../user/user.service';
import { LoginDto } from './dto/login.dto';
import { CreateUserDto } from '../user/dto/create-user.dto';
import axios from 'axios';
import { randomBytes } from 'crypto';
import { MailService } from 'src/mail/mail.service';
import * as crypto from 'crypto';
@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    public readonly jwtService: JwtService,
    private mailService: MailService,
    @InjectModel(User.name) private readonly userModel: Model<User>,
  ) {}

  // Signup function to create a new user
  async signup(createUserDto: CreateUserDto) {
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
  
    const verificationToken = crypto.randomBytes(32).toString('hex');
  
    const user = await this.userService.create({
      ...createUserDto,
      password: hashedPassword,
      emailVerified: false, // Ensure email is marked unverified
      emailVerificationToken: verificationToken, // Add verification token
      emailVerificationExpires: Date.now() + 3600000, // Set expiration
    });
  
    const verificationUrl = `http://localhost:3000/auth/verify-email?token=${verificationToken}`;
    await this.mailService.sendVerificationEmail(user.email, verificationUrl);
  
    return { message: 'Signup successful. Please verify your email.' };
  }

  // Add validateUser method to check user credentials
  

  // Adjusted login method to accept a User object instead of email/password
  async login(user: User): Promise<{ access_token: string }> {
    const payload = { email: user.email, sub: user._id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  // Function to validate and handle Google user login
  async googleLogin(code: string) {
    try {
      const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', null, {
        params: {
          code,
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          redirect_uri: 'http://localhost:3000/auth/google/callback',
          grant_type: 'authorization_code',
        },
      });
  
      const { access_token } = tokenResponse.data;
      if (!access_token) {
        console.error('Error: Access token not received');
        throw new UnauthorizedException('Google login failed - No access token');
      }
  
      const userProfileResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${access_token}` },
      });
  
      const { id: googleId, given_name: firstName, family_name: lastName, email } = userProfileResponse.data;
      let user = await this.userModel.findOne({ email });
  
      if (!user) {
        const newUser = new this.userModel({
          email,
          googleId,
          nom: lastName,
          prenom: firstName,
          password: null,
        });
        user = await newUser.save();
      }
  
      const payload = { email: user.email, sub: user._id };
      const accessToken = this.jwtService.sign(payload);
  
      return { access_token: accessToken, user };
    } catch (error) {
      console.error('Google login error details:', error.response?.data || error.message);
      throw new UnauthorizedException('Google login failed');
    }
  }

  async validateGoogleUser(googleId: string, firstName: string, lastName: string, email: string) {
    let user = await this.userModel.findOne({ email });
    if (!user) {
      const newUser = new this.userModel({
        email,
        googleId,
        nom: lastName,
        prenom: firstName,
      });
      user = await newUser.save();
    }
    return user;
  }

  // Function to handle password reset request (send email with token)
  async requestPasswordReset(email: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const resetToken = randomBytes(32).toString('hex'); // Generate a random reset token
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex'); // Hash the token

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = Date.now() + 3600000; // Token expires in 1 hour
    await this.userService.saveResetToken(user._id.toString(), hashedToken); // Save token and expiration

    await this.mailService.sendResetPasswordEmail(email, resetToken); // Send the reset code to the user via email
  }

  // Function to handle the reset of the password with the provided reset token
  async resetPassword(resetToken: string, newPassword: string): Promise<void> {
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex'); // Hash the incoming reset token

    console.log(`Reset Token (incoming): ${resetToken}`);
    console.log(`Hashed Token (calculated): ${hashedToken}`);

    const user = await this.userModel.findOne({
        resetPasswordToken: hashedToken, // Compare hashed token
        resetPasswordExpires: { $gt: Date.now() }, // Ensure token is not expired
    });

    if (!user) {
        throw new UnauthorizedException('Invalid or expired reset token');
    }

    // Update the user's password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetPasswordToken = null; // Clear the reset token
    user.resetPasswordExpires = null; // Clear the expiration
    await user.save();

    console.log('Password updated successfully for user:', user.email);
}

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userService.findByEmail(email);
  
    if (!user) {
      return null;
    }
  
    if (!user.emailVerified) {
      throw new UnauthorizedException('Please verify your email before logging in.');
    }
  
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return null;
    }
  
    return user;
  }
  
}