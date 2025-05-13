import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../../common/decorators/role.decorator';
import { Observable } from 'rxjs';

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private reflector: Reflector) { }

    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
            context.getHandler(),
            context.getClass(),
        ])

        if (!requiredRoles) {
            return true;
        }

        const request = context.switchToHttp().getRequest()
        const user = request.user;

        if (!user || !requiredRoles.includes(user.role)) {
            throw new ForbiddenException('Access Denied');
        }
        return true;
    }

}