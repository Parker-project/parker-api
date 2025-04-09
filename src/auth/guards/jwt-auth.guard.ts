import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtAuthGuard implements CanActivate {
    constructor(private readonly configService: ConfigService) { }
    canActivate(context: ExecutionContext): boolean {
        const req = context.switchToHttp().getRequest();
        const token = req.cookies?.access_token;
        console.log("🚀 ~ JwtAuthGuard ~ canActivate ~ token:", req)

        if (!token) throw new UnauthorizedException('Access denied');

        try {
            const decoded = jwt.verify(token, this.configService.get<string>('JWT_SECRET')!);
            console.log("🚀 ~ JwtAuthGuard ~ canActivate ~ decoded:", decoded)
            req.user = decoded;
            return true;
        } catch {
            throw new UnauthorizedException('Invalid token');
        }
    }
}