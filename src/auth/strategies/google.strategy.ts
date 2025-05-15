import { Injectable, Inject, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, StrategyOptions } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private configService: ConfigService,
    @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: Logger,
  ) {
    super({
      clientID: configService.getOrThrow<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.getOrThrow<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.getOrThrow<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    } as StrategyOptions);
  }

  async validate(accessToken: string, refreshToken: string, profile: any): Promise<any> {
    try {
      this.logger.debug(`Google profile: ${JSON.stringify(profile, null, 2)}`, 'GoogleStrategy');
      this.logger.debug(`Access token: ${accessToken}`, 'GoogleStrategy');
      this.logger.debug(`Refresh token: ${refreshToken}`, 'GoogleStrategy');

      const { name, emails, photos } = profile;

      const email = emails?.[0]?.value;
      if (!email) {
        throw new Error('No email found in Google profile');
      }

      return {
        email,
        firstName: name?.givenName || '',
        lastName: name?.familyName || '',
        picture: photos?.[0]?.value || '',
        role: 'user',
      };
    } catch (error) {
      this.logger.error(`Failed to validate Google user: ${error.message}`, undefined, 'GoogleStrategy');
      throw error;
    }
  }
}
