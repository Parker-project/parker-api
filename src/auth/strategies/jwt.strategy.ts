// src/auth/strategies/jwt.strategy.ts
import { Inject, Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService, @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: Logger,
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
      return { id: payload.sub, email: payload.email, role: payload.role, firstName: payload.firstName, isEmailVerified: payload.isEmailVerified };
    }
    catch (error) {
      this.logger.error(`Failed to validate user: ${error.message}`, undefined, 'JwtStrategy');
      throw error;
    }
  }
}
