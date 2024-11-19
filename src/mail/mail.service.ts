import { Injectable } from '@nestjs/common';
import axios from 'axios';

@Injectable()
export class MailService {
  private readonly brevoApiUrl = 'https://api.brevo.com/v3/smtp/email';

  /**
   * Send a reset password email.
   * @param to Recipient email address.
   * @param resetCode Reset code for the password reset.
   */
  async sendResetPasswordEmail(to: string, resetCode: string) {
    const emailData = {
      sender: { name: "Yshopmate", email: "azizabidilol7@gmail.com" },  // Replace with your sender email
      to: [{ email: to }],
      subject: 'Password Reset Code',
      htmlContent: `
        <p>Hello,</p>
        <p>You requested a password reset. Use the code below to reset your password:</p>
        <h2>${resetCode}</h2>
        <p>If you did not request this, please ignore this email.</p>
      `,
    };

    try {
      const response = await axios.post(this.brevoApiUrl, emailData, {
        headers: {
          'api-key': process.env.BREVO_API_KEY,  // Using the API key from .env
          'Content-Type': 'application/json',
        },
      });
      console.log('Reset password email sent:', response.data);
    } catch (error) {
      console.error('Error sending reset password email:', error.response?.data || error.message);
      throw new Error('Failed to send reset password email');
    }
  }

  /**
   * Send a verification email.
   * @param email Recipient email address.
   * @param verificationUrl The URL containing the verification token.
   */
  async sendVerificationEmail(email: string, verificationUrl: string) {
    const emailData = {
      sender: { name: "shopmate", email: "azizabidilol7@gmail.com" }, // Replace with your sender email
      to: [{ email }],
      subject: 'Verify Your Email Address',
      htmlContent: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #f0f0f0; border-radius: 10px;">
          <h2 style="text-align: center; color: #333;">Welcome to Yshopmate!</h2>
          <p style="color: #555;">Hi there,</p>
          <p style="color: #555;">Thank you for signing up for Yshopmate. Please verify your email address to activate your account by clicking the button below:</p>
          <div style="text-align: center; margin: 20px 0;">
            <a href="${verificationUrl}" style="background-color: #007bff; color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; font-size: 16px;">Verify Email</a>
          </div>
          <p style="color: #555;">If you did not sign up for this account, please ignore this email.</p>
          <p style="color: #555;">Best regards,</p>
          <p style="color: #333;"><strong>The Yshopmate Team</strong></p>
        </div>
      `,
    };
  
    try {
      const response = await axios.post(this.brevoApiUrl, emailData, {
        headers: {
          'api-key': process.env.BREVO_API_KEY,  // Using the API key from .env
          'Content-Type': 'application/json',
        },
      });
      console.log('Verification email sent:', response.data);
    } catch (error) {
      console.error('Error sending verification email:', error.response?.data || error.message);
      throw new Error('Failed to send verification email');
    }
  }
}