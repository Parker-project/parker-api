import {  Body, Controller, Get, Inject, Logger, Param, Patch, Post, Req, Res, UseGuards } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthGuard } from '@nestjs/passport';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Response, Request } from 'express';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';

import { CreateUserDto } from './dto/create-user.dto';
import { MailDto } from './dto/mail.dto';
import { UserLoginDto } from './dto/user-login.dto';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { ResetPasswordDto } from './dto/reset-password.dto';


@Controller('auth')
@ApiTags('Auth')
export class AuthController {
    constructor(private readonly authService: AuthService, private readonly configService: ConfigService, @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: Logger) { }

    @Post('signup')
    @ApiOperation({ summary: 'Register a new user account' })
    @ApiBody({ type: CreateUserDto })
    @ApiResponse({ status: 201, description: 'User created successfully' })
    @ApiResponse({ status: 400, description: 'Validation error' })
    async signup(@Body() createUserDTO: CreateUserDto) {
        try {
            this.logger.log('User signup request received', 'AuthController');
            return await this.authService.signup(createUserDTO);
        } catch (error) {
            this.logger.error(`Signup error: ${error.message}`, undefined, 'AuthController');
            throw error;
        }
    }

    @Get('verify-email/:token')
    @ApiOperation({ summary: 'Verify user email directly from link' })
    @ApiResponse({ status: 200, description: 'Email verified and redirected to login' })
    async verifyEmailDirectly(@Param('token') token: string, @Res() res: Response) {
        try {
            this.logger.log(`Email verification request with token: ${token.substring(0, 8)}...`, 'AuthController');

            await this.authService.verifyEmailDirect(token);

            // Redirect to login page with success message
            return res.redirect(`${this.configService.get('FRONTEND_URL')}/login?verified=true`);
        } catch (error) {
            this.logger.error(`Direct email verification failed: ${error.message}`, undefined, 'AuthController');

            // Redirect to login page with error message
            return res.redirect(`${this.configService.get('FRONTEND_URL')}/login?verified=false}`);
        }
    }

    @Patch('resend-verification')
    @ApiOperation({ summary: 'Resend email verification link' })
    @ApiBody({ type: MailDto })
    @ApiResponse({ status: 200, description: 'Email sent' })
    async resendVerificationEmail(@Body() resendVerification: MailDto, @Res() res: Response) {
        return await this.authService.resendVerification(resendVerification.email);

    }

    @Post('login')
    @ApiOperation({ summary: 'Login user and set access token cookie' })
    @ApiBody({ type: UserLoginDto })
    @ApiResponse({ status: 200, description: 'Login success' })
    @ApiResponse({ status: 401, description: 'Invalid credentials' })
    async login(@Body() userLoginDto: UserLoginDto, @Res({ passthrough: true }) res: Response) {
        const { accessToken, sanitizedUser } = await this.authService.login(userLoginDto);

        // Set cookie
        res.cookie('access_token', accessToken, {
            httpOnly: true,
            secure: this.configService.getOrThrow<string>('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: userLoginDto.rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000 // 30 days or 1 day
        });

        return { message: 'Logged in successfully', sanitizedUser };
    }

    @UseGuards(JwtAuthGuard)
    @Post('logout')
    @ApiOperation({ summary: 'Logout user and clear access token cookie' })
    @ApiBody({ type: MailDto })
    @ApiResponse({ status: 200, description: 'Email sent' })
    logout(@Res({ passthrough: true }) res: Response) {
        res.clearCookie('access_token', {
            httpOnly: true,
            secure: this.configService.get('NODE_ENV') === 'production',
            sameSite: 'strict',
        });
        return { message: 'Logged out successfully' };
    }

    @UseGuards(AuthGuard('google'))
    @Get('google')
    @ApiOperation({ summary: 'Redirect user to Google login page' })
    async googleAuth() {
        this.logger.log('Google authentication redirect', 'AuthController');
        // redirect to Google
    }

    @UseGuards(GoogleAuthGuard)
    @Get('google/callback')
    @ApiOperation({ summary: 'Google callback endpoint that sets access token cookie' })
    @ApiResponse({ status: 302, description: 'Redirect to frontend with user info' })
    async googleAuthRedirect(@Req() req: Request, @Res() res: Response) {
        try {
            this.logger.log('Google callback received', 'AuthController');

            if (!req.user) {
                this.logger.warn('Google auth callback without user data', 'AuthController');
                return res.redirect(`${this.configService.get('FRONTEND_URL')}/login?error=google_auth_failed`);
            }

            this.logger.log(`Processing Google user data: ${JSON.stringify(req.user)}`, 'AuthController');
            const { accessToken, sanitizedUser } = await this.authService.handleGoogleLogin(req.user as any);

            // Set cookie
            res.cookie('access_token', accessToken, {
                httpOnly: true,
                secure: this.configService.get('NODE_ENV') === 'production',
                sameSite: 'strict',
                maxAge: 30 * 24 * 60 * 60 * 1000
            });

            this.logger.log(`Google login successful for user: ${sanitizedUser.email}`, 'AuthController');

            // Redirect to dashboard with success status
            return res.redirect(`${this.configService.get('FRONTEND_URL')}/dashboard?login=success`);
            //return { message: 'Logged in successfully', sanitizedUser };
        } catch (error) {
            this.logger.error(`Google auth callback error: ${error.message}`, error.stack, 'AuthController');
            return res.redirect(`${this.configService.get('FRONTEND_URL')}/login?error=google_auth_failed`);
        }
    }

    @Post('request-password-reset')
    @ApiOperation({ summary: 'Send password reset email' })
    @ApiResponse({ status: 200, description: 'Reset link sent if user exists' })
    async forgotPassword(@Body() dto: MailDto) {
        try {
            this.logger.log(`Password reset request for: ${dto.email}`, 'AuthController');
            return await this.authService.sendPasswordResetEmail(dto.email);
        } catch (error) {
            throw error;
        }
    }

    @Patch('reset-password')
    @ApiOperation({ summary: 'Reset password using reset token' })
    @ApiResponse({ status: 200, description: 'Password reset successful' })
    @ApiResponse({ status: 400, description: 'Invalid or expired token' })
    async resetPassword(@Body() dto: ResetPasswordDto) {
        this.logger.log('Password reset attempt with token', 'AuthController');
        return await this.authService.resetPassword(dto.token, dto.password);
    }
}