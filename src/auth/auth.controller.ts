import { BadRequestException, Body, Controller, Get, LoggerService, Patch, Post, Req, Res, UseGuards } from '@nestjs/common';
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
    constructor(private readonly authService: AuthService, private readonly configService: ConfigService, private readonly logger: LoggerService) { }

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
            this.logger.error(`Signup error: ${error.message}`, error.stack, 'AuthController');
            throw error;
        }
    }

    @Patch('verify-email')
    @ApiOperation({ summary: 'Verify user email with token' })
    @ApiBody({ type: VerifyEmailDto })
    @ApiResponse({ status: 200, description: 'Email verified' })
    @ApiResponse({ status: 400, description: 'Invalid token' })
    async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto, @Res() res: Response) {
        try {
            if (!verifyEmailDto.verificationToken) {
                this.logger.warn('Verification attempt with missing token', 'AuthController');
                throw new BadRequestException('Invalid verification token');
            }
            this.logger.log('Email verification request received', 'AuthController');
            return await this.authService.verifyEmail(verifyEmailDto);
        } catch (error) {
            this.logger.error(`Email verification error: ${error.message}`, error.stack, 'AuthController');
            throw error;
        }
    }

    @Patch('resend-verification')
    @ApiOperation({ summary: 'Resend email verification link' })
    @ApiBody({ type: MailDto })
    @ApiResponse({ status: 200, description: 'Email sent' })
    async resendVerificationEmail(@Body() resendVerification: MailDto, @Res() res: Response) {
        try {
            this.logger.log(`Resend verification request for: ${resendVerification.email}`, 'AuthController');
            return await this.authService.resendVerification(resendVerification.email);
        } catch (error) {
            this.logger.error(`Resend verification error: ${error.message}`, error.stack, 'AuthController');
            throw error;
        }
    }

    @Post('login')
    @ApiOperation({ summary: 'Login user and set access token cookie' })
    @ApiBody({ type: UserLoginDto })
    @ApiResponse({ status: 200, description: 'Login success' })
    @ApiResponse({ status: 401, description: 'Invalid credentials' })
    async login(@Body() userLoginDto: UserLoginDto, @Res({ passthrough: true }) res: Response) {
        try {
            this.logger.log(`Login attempt for: ${userLoginDto.email}`, 'AuthController');

            const { accessToken, sanitizedUser } = await this.authService.login(userLoginDto);

            // Set cookie
            res.cookie('access_token', accessToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: userLoginDto.rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000 // 30 days or 1 day
            });

            return { message: 'Logged in successfully', sanitizedUser };
        } catch (error) {
            this.logger.error(`Login error: ${error.message}`, error.stack, 'AuthController');
            throw error;
        }
    }

    @UseGuards(JwtAuthGuard)
    @Post('logout')
    @ApiOperation({ summary: 'Logout user and clear access token cookie' })
    @ApiBody({ type: MailDto })
    @ApiResponse({ status: 200, description: 'Email sent' })
    logout(@Res({ passthrough: true }) res: Response) {
        try {
            this.logger.log('User logout request received', 'AuthController');

            res.clearCookie('access_token', {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
            });

            return { message: 'Logged out successfully' };
        } catch (error) {
            this.logger.error(`Logout error: ${error.message}`, error.stack, 'AuthController');
            throw error;
        }
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
            this.logger.log('Google authentication callback received', 'AuthController');

            if (!req.user) {
                this.logger.warn('Google auth callback without user data', 'AuthController');
                return res.redirect(`${this.configService.get('FRONTEND_URL')}/login?error=google_auth_failed`);
            }

            const { accessToken } = await this.authService.handleGoogleLogin(req.user as any);

            // Set cookie
            res.cookie('access_token', accessToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
            });
            return res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
        } catch (error) {
            this.logger.error(`Google auth error: ${error.message}`, error.stack, 'AuthController');
            return res.redirect(`${this.configService.get('FRONTEND_URL')}/login`);
        }
    }

    @Post('forgot-password')
    @ApiOperation({ summary: 'Send password reset email' })
    @ApiResponse({ status: 200, description: 'Reset link sent if user exists' })
    async forgotPassword(@Body() dto: MailDto) {
        try {
            this.logger.log(`Password reset request for: ${dto.email}`, 'AuthController');
            return await this.authService.sendPasswordResetEmail(dto.email);
        } catch (error) {
            this.logger.error(`Password reset request error: ${error.message}`, error.stack, 'AuthController');
            throw error;
        }    }

    @Post('reset-password')
    @ApiOperation({ summary: 'Reset password using reset token' })
    @ApiResponse({ status: 200, description: 'Password reset successful' })
    @ApiResponse({ status: 400, description: 'Invalid or expired token' })
    async resetPassword(@Body() dto: ResetPasswordDto) {
        try {
            this.logger.log('Password reset attempt with token', 'AuthController');
            return await this.authService.resetPassword(dto.token, dto.password);
        } catch (error) {
            this.logger.error(`Password reset error: ${error.message}`, error.stack, 'AuthController');
            throw error;
        }    }
}