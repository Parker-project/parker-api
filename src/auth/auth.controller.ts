import { BadRequestException, Body, Controller, Get, Patch, Post, Req, Res, UseGuards } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthGuard } from '@nestjs/passport';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Response, Request } from 'express';


import { CreateUserDto } from './dto/create-user.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { MailDto } from './dto/mail.dto';
import { UserLoginDto } from './dto/user-login.dto';
import { AuthService } from './auth.service';
import { RolesGuard } from './guards/role.guard';
import { Role } from 'src/common/enums/role.enum';
import { Roles } from 'src/common/decorators/role.decorator';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { ResetPasswordDto } from './dto/reset-password.dto';


@Controller('auth')
@ApiTags('Auth')
export class AuthController {
    constructor(private readonly authService: AuthService, private readonly configService: ConfigService) { }

    @Post('signup')
    @ApiOperation({ summary: 'Register a new user account' })
    @ApiBody({ type: CreateUserDto })
    @ApiResponse({ status: 201, description: 'User created successfully' })
    @ApiResponse({ status: 400, description: 'Validation error' })
    signup(@Body() createUserDTO: CreateUserDto) {
        return this.authService.signup(createUserDTO)
    }

    @Patch('verify-email')
    @ApiOperation({ summary: 'Verify user email with token' })
    @ApiBody({ type: VerifyEmailDto })
    @ApiResponse({ status: 200, description: 'Email verified' })
    @ApiResponse({ status: 400, description: 'Invalid token' })
    async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto, @Res() res: Response) {
        if (!verifyEmailDto.verificationToken) {
            throw new BadRequestException('Invalid verification token');
        }
        return await this.authService.verifyEmail(verifyEmailDto)
    }

    @Patch('resend-verification')
    @ApiOperation({ summary: 'Resend email verification link' })
    @ApiBody({ type: MailDto })
    @ApiResponse({ status: 200, description: 'Email sent' })
    async resendVerificationEmail(@Body() resendVerification: MailDto, @Res() res: Response) {
        return await this.authService.resendVerification(resendVerification.email)
    }

    @Post('login')
    @ApiOperation({ summary: 'Login user and set access token cookie' })
    @ApiBody({ type: UserLoginDto })
    @ApiResponse({ status: 200, description: 'Login success' })
    @ApiResponse({ status: 401, description: 'Invalid credentials' })
    async login(@Body() userLoginDto: UserLoginDto, @Res({ passthrough: true }) res: Response) {
        const { accessToken, sanitizedUser } = await this.authService.login(userLoginDto);

        res.cookie('access_token', accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: userLoginDto.rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000 // 30 days or 1 day
        })
        
        return { message: 'Logged in successfully', user: sanitizedUser };
    }

    @UseGuards(JwtAuthGuard)
    @Post('logout')
    @ApiOperation({ summary: 'Logout user and clear access token cookie' })
    @ApiBody({ type: MailDto })
    @ApiResponse({ status: 200, description: 'Email sent' })
    logout(@Res({ passthrough: true }) res: Response) {
        res.clearCookie('access_token', {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
        });

        return { message: 'Logged out successfully' }
    }

    @UseGuards(AuthGuard('google'))
    @Get('google')
    @ApiOperation({ summary: 'Redirect user to Google login page' })
    async googleAuth() {
        // redirect to Google
    }

    @UseGuards(GoogleAuthGuard)
    @Get('google/callback')
    @ApiOperation({ summary: 'Google callback endpoint that sets access token cookie' })
    @ApiResponse({ status: 302, description: 'Redirect to frontend with user info' })
    async googleAuthRedirect(@Req() req: Request, @Res() res: Response) {
        const { accessToken } = await this.authService.handleGoogleLogin(req.user as any);

        res.cookie('accessToken', accessToken, { httpOnly: true });

        return res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
    }

    @Post('forgot-password')
    @ApiOperation({ summary: 'Send password reset email' })
    @ApiResponse({ status: 200, description: 'Reset link sent if user exists' })
    async forgotPassword(@Body() dto: MailDto) {
        return this.authService.sendPasswordResetEmail(dto.email);
    }

    @Post('reset-password')
    @ApiOperation({ summary: 'Reset password using reset token' })
    @ApiResponse({ status: 200, description: 'Password reset successful' })
    @ApiResponse({ status: 400, description: 'Invalid or expired token' })
    async resetPassword(@Body() dto: ResetPasswordDto) {
        return this.authService.resetPassword(dto.token, dto.password);
    }
}