import { BadRequestException, Body, Controller, Get, Patch, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResendVerificationDto } from './dto/resend-verification.dto';
import { UserLoginDto } from './dto/user-login.dto';
import { Response, Request } from 'express';
import { RolesGuard } from './guards/role.guard';
import { Role } from 'src/common/enums/role.enum';
import { Roles } from 'src/common/decorators/role.decorator';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ConfigService } from '@nestjs/config';
import { AuthGuard } from '@nestjs/passport';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';


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
    verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
        if (!verifyEmailDto.verificationToken) {
            throw new BadRequestException('Invalid verification token');
        }
        return this.authService.verifyEmail(verifyEmailDto)
    }

    @Patch('resend-verification')
    @ApiOperation({ summary: 'Resend email verification link' })
    @ApiBody({ type: ResendVerificationDto })
    @ApiResponse({ status: 200, description: 'Email sent' })
    resendVerificationEmail(@Body() resendVerification: ResendVerificationDto) {
        return this.authService.resendVerification(resendVerification.email)
    }

    @Post('login')
    @ApiOperation({ summary: 'Login user and set access token cookie' })
    @ApiBody({ type: UserLoginDto })
    @ApiResponse({ status: 200, description: 'Login success' })
    @ApiResponse({ status: 401, description: 'Invalid credentials' })
    async login(@Body() userLoginDto: UserLoginDto, @Res({ passthrough: true }) res: Response) {
        const { accessToken, user } = await this.authService.login(userLoginDto);

        res.cookie('access_token', accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: userLoginDto.rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000 // 30 days or 1 day
        })
        return { message: 'Logged in successfully', user }
    }

    @UseGuards(JwtAuthGuard)
    @Post('logout')
    @ApiOperation({ summary: 'Logout user and clear access token cookie' })
    @ApiBody({ type: ResendVerificationDto })
    @ApiResponse({ status: 200, description: 'Email sent' })
    logout(@Res({ passthrough: true }) res: Response) {
        res.clearCookie('access_token', {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
        });

        return { message: 'Logged out successfully' };
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
        const { accessToken, user } = await this.authService.handleGoogleLogin(req.user as any);

        res.cookie('accessToken', accessToken, { httpOnly: true });

        return { message: 'Logged in successfully', user }
    }
}