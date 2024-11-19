// src/auth/guards/google-auth.guard.ts
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {
  // You can customize the behavior here if needed
  // For example, you can add logging or handle specific cases when authentication fails
}
