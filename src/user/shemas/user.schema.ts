// src/user/schemas/user.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class User extends Document {
  @Prop({ required: true })
  nom: string;

  @Prop({ required: true })
  prenom: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop()
  password?: string;  // Make password optional for Google users

  @Prop()
  historiqueAchat: string[];

  @Prop()
  preferences: string[];

  // Add resetPasswordToken to store the reset token
  @Prop({ required: false, default: null })
  resetPasswordToken?: string;

  // Add resetPasswordExpires to store the expiration date of the token
  @Prop({ required: false, default: null })
  resetPasswordExpires?: number;
  
  @Prop({ default: false })
emailVerified: boolean; // Indicates whether the email is verified

@Prop()
emailVerificationToken?: string; // Stores the verification token

@Prop()
emailVerificationExpires?: number; // Expiration time for the token
}


export const UserSchema = SchemaFactory.createForClass(User);
