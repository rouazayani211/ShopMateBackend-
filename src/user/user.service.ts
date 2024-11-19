import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './shemas/user.schema';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { MailService } from 'src/mail/mail.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UserService {
  constructor(
    private readonly mailService: MailService,
    @InjectModel(User.name) private readonly userModel: Model<User>
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const createdUser = new this.userModel(createUserDto);
    return createdUser.save();
  }

  async findAll(): Promise<User[]> {
    return this.userModel.find().exec();
  }

  async findOne(id: string): Promise<User> {
    return this.userModel.findById(id).exec();
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    return this.userModel.findByIdAndUpdate(id, updateUserDto, { new: true });
  }

  async remove(id: string): Promise<User> {
    return this.userModel.findByIdAndDelete(id).exec();
  }

  async findByEmail(email: string): Promise<User | undefined> {
    return this.userModel.findOne({ email }).exec();
  }

  async saveResetToken(userId: string, resetToken: string): Promise<void> {
    const expirationDate = new Date();
    expirationDate.setHours(expirationDate.getHours() + 1); // Token expires in 1 hour

    // Hash the reset token before saving
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    await this.userModel.updateOne(
        { _id: userId },
        {
            resetPasswordToken: hashedToken, // Save hashed token
            resetPasswordExpires: expirationDate.getTime(), // Save expiration
        }
    );

    console.log(`Saving Reset Token (hashed): ${hashedToken}`);
}

  async findByResetToken(resetToken: string): Promise<User | undefined> {
    console.log(`Searching for reset token in database: ${resetToken}`);
  
    const user = await this.userModel.findOne({
      resetPasswordToken: resetToken, // Compare plaintext tokens
      resetPasswordExpires: { $gt: Date.now() }, // Ensure token is still valid
    }).exec();
  
    console.log(`User found: ${JSON.stringify(user)}`);
    return user;
  }

  async updatePassword(userId: string, newPassword: string): Promise<void> {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.userModel.updateOne(
      { _id: userId },
      {
        password: hashedPassword,
        resetPasswordToken: null,
        resetPasswordExpires: null,
      }
    );
  }

  async forgotPassword(email: string): Promise<{ message: string }> {
    const user = await this.userModel.findOne({ email });

    if (!user) {
        throw new NotFoundException('User with this email does not exist.');
    }

    const resetToken = Math.floor(100000 + Math.random() * 900000).toString(); // Generate 6-digit code

    // Save the hashed token in the database
    await this.saveResetToken(user._id.toString(), resetToken);

    // Send the plaintext token via email
    await this.mailService.sendResetPasswordEmail(email, resetToken);

    return { message: 'Password reset code has been sent to your email address.' };
}

  async resetPasswordWithCode(resetCode: string, newPassword: string): Promise<{ message: string }> {
    const user = await this.userModel.findOne({
      resetPasswordToken: resetCode,
      resetPasswordExpires: { $gt: Date.now() }, // Check if token is expired
    });

    if (!user) {
      throw new NotFoundException('Invalid or expired reset code.');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;

    await user.save();

    return { message: 'Password has been reset successfully.' };
  }
  async findByVerificationToken(token: string): Promise<User | undefined> {
    return this.userModel.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: Date.now() }, // Ensure token is still valid
    }).exec();
  }
  async updateUser(
    id: string,
    updateData: { nom: string; prenom: string; email: string; password?: string }
  ): Promise<User> {
    const user = await this.userModel.findById(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (updateData.nom) user.nom = updateData.nom;
    if (updateData.prenom) user.prenom = updateData.prenom;
    if (updateData.email) user.email = updateData.email;
    if (updateData.password) {
      // Hash the password before saving (if needed)
      const hashedPassword = await this.hashPassword(updateData.password);
      user.password = hashedPassword;
    }

    return user.save();
  }

  private async hashPassword(password: string): Promise<string> {
    const bcrypt = require('bcrypt');
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
  }
}