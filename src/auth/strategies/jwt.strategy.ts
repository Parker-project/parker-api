// src/auth/strategies/jwt.strategy.ts
import { Injectable, LoggerService } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService, private readonly logger: LoggerService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req) => {
          return req?.cookies?.['access_token'];
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow<string>('JWT_SECRET'),
    });
  }

  async validate(payload: any) {
    this.logger.log(`Validating user ${payload.email}`)
    try {
      return { email: payload.email, role: payload.role, firstName: payload.firstName, lastName: payload.lastName };
    }
    catch (error) {
      this.logger.error(`Failed to validate user: ${error.message}`, error.stack);
      throw error;
    }
  }
}
