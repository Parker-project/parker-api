import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UserDto } from './dto/user.dto';
import { Request } from 'express';

@Controller('user')
export class UserController {
    @Get('profile')
    @UseGuards(JwtAuthGuard)
    @ApiOperation({ summary: 'Get the authenticated user\'s information' })
    @ApiResponse({ status: 200, description: 'Returns the authenticated user\'s details.', type: UserDto })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    async getProfile(@Req() req: Request): Promise<UserDto> {
        return req.user as UserDto;
    }
}
