import { BadRequestException, Body, Controller, Patch, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResendVerificationDto } from './dto/resend-verification.dto';
import { UserLoginDto } from './dto/user-login.dto';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

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
        const { token, user } = await this.authService.login(userLoginDto);

        res.cookie('access_token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: userLoginDto.rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000 // 30 days or 1 day
        })
        return { message: 'Logged in successfully', user }
    }

    @Post('logout')
    logout(@Res({ passthrough: true }) res: Response) {
        res.clearCookie('access_token', {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
        });

        return { message: 'Logged out successfully' };
    }
}
