// dto/request-reset-password.dto.ts

// dto/reset-password.dto.ts
import { IsString } from 'class-validator';

export class ResetPasswordDto {
  @IsString()
  resetToken: string;

  @IsString()
  newPassword: string;
}