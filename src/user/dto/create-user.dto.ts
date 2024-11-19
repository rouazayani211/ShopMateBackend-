import { IsOptional, IsBoolean } from 'class-validator';

// src/user/dto/create-user.dto.ts
export class CreateUserDto {
    readonly nom: string;
    readonly prenom: string;
    readonly email: string;
    readonly password: string;  // Add password field here
    readonly historiqueAchat?: string[];
    readonly preferences?: string[];
    @IsOptional()
  emailVerified?: boolean;

  @IsOptional()
  emailVerificationToken?: string;

  @IsOptional()
  emailVerificationExpires?: number;

  }
  