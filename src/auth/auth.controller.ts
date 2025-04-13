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


@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService, private readonly configService: ConfigService) { }

    @Post('signup')
    signup(@Body() createUserDTO: CreateUserDto) {
        return this.authService.signup(createUserDTO)
    }

    @Patch('verify-email')
    verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
        if (!verifyEmailDto.verificationToken) {
            throw new BadRequestException('Invalid verification token');
        }
        return this.authService.verifyEmail(verifyEmailDto)
    }

    @Patch('resend-verification')
    resendVerificationEmail(@Body() resendVerification: ResendVerificationDto) {
        return this.authService.resendVerification(resendVerification.email)
    }

    @Post('login')
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
    async googleAuth() {
        // redirect to Google
    }

    @UseGuards(GoogleAuthGuard)
    @Get('google/callback')
    async googleAuthRedirect(@Req() req: Request, @Res() res: Response) {
        const { accessToken, user } = await this.authService.handleGoogleLogin(req.user as any);

        res.cookie('accessToken', accessToken, { httpOnly: true });

        return res.redirect(this.configService.getOrThrow<string>('FRONTEND_URL)'));
    }
}