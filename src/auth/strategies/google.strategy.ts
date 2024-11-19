import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { AuthService } from '../auth.service';
import { JwtService } from '@nestjs/jwt';  // Import JwtService here

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private authService: AuthService,
    private jwtService: JwtService,  // Inject JwtService directly here
  ) {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/callback',
      scope: ['email', 'profile'],
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: any) {
    const { name, emails, id } = profile;
    const user = await this.authService.validateGoogleUser(id, name.givenName, name.familyName, emails[0].value);

    const payload = { email: user.email, sub: user._id };
    const jwtToken = this.jwtService.sign(payload);  // Use the injected JwtService

    return { user, jwtToken };
  }
}
