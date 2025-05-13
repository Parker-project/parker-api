import { Controller, Get, Req, UseGuards, Param, NotFoundException } from '@nestjs/common';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UserDto } from './dto/user.dto';
import { Request } from 'express';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
    constructor(private readonly userService: UserService) { }

    @Get('profile')
    @UseGuards(JwtAuthGuard)
    @ApiOperation({ summary: 'Get the authenticated user\'s information' })
    @ApiResponse({ status: 200, description: 'Returns the authenticated user\'s details.', type: UserDto })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    async getProfile(@Req() req: Request): Promise<UserDto> {
        return req.user as UserDto;
    }

    @Get('email/:email')
    @UseGuards(JwtAuthGuard)
    @ApiOperation({ summary: 'Find user by email' })
    @ApiResponse({ status: 200, description: 'Returns the user details if found.', type: UserDto })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'User not found' })
    async findByEmail(@Param('email') email: string): Promise<UserDto> {
        const user = await this.userService.findUserByEmail(email);
        if (!user) {
            throw new NotFoundException('User not found');
        }
        return user;
    }
}
