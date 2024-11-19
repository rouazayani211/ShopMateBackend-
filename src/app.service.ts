import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppService {
  constructor(private configService: ConfigService) {}

  getHello(): string {
    // Access the environment variables using ConfigService
    const googleClientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
    const googleClientSecret = this.configService.get<string>('GOOGLE_CLIENT_SECRET');

    // Log the variables to the console to check if they are loaded
    console.log('Google Client ID:', googleClientId);
    console.log('Google Client Secret:', googleClientSecret);

    return 'Hello World!';
  }
}
