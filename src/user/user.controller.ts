import { Controller, Get, Req, UseGuards, Param, NotFoundException, Patch, Delete, Body } from '@nestjs/common';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UserDto } from './dto/user.dto';
import { Request } from 'express';
import { UserService } from './user.service';
import { Role } from '../common/enums/role.enum';
import { Roles } from 'src/common/decorators/role.decorator';
import { RolesGuard } from 'src/auth/guards/role.guard';

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
    @UseGuards(RolesGuard)
    @Roles(Role.Admin)
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

    @Get()
    @UseGuards(JwtAuthGuard)
    @UseGuards(RolesGuard)
    @Roles(Role.Admin)
    @ApiOperation({ summary: 'Get all users' })
    @ApiResponse({ status: 200, description: 'Returns a list of all users.', type: [UserDto] })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    async findAll(): Promise<UserDto[]> {
        return this.userService.findAll();
    }

    @Get(':id')
    @UseGuards(JwtAuthGuard)
    @UseGuards(RolesGuard)
    @Roles(Role.Admin)
    @ApiOperation({ summary: 'Get user by ID' })
    @ApiResponse({ status: 200, description: 'Returns the user details if found.', type: UserDto })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'User not found' })
    async findById(@Param('id') id: string): Promise<UserDto> {
        return this.userService.findById(id);
    }

    @Patch(':id/role')
    @UseGuards(JwtAuthGuard)
    @UseGuards(RolesGuard)
    @Roles(Role.Admin)
    @ApiOperation({ summary: 'Update user role' })
    @ApiResponse({ status: 200, description: 'User role updated successfully.', type: UserDto })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'User not found' })
    async updateRole(
        @Param('id') id: string,
        @Body('role') role: Role
    ): Promise<UserDto> {
        return this.userService.updateRole(id, role);
    }

    @Delete(':id')
    @UseGuards(JwtAuthGuard)
    @ApiOperation({ summary: 'Delete user' })
    @ApiResponse({ status: 200, description: 'User deleted successfully' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'User not found' })
    async delete(@Param('id') id: string) {
        return this.userService.delete(id);
    }
}
