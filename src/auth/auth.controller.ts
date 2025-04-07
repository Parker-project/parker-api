import { BadRequestException, Body, Controller, Patch, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResendVerificationDto } from './dto/resend-verification.dto';

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
    resendVerificationEmail(@Body() resendVerification: ResendVerificationDto){
        return this.authService.resendVerification(resendVerification.email)
    }
}
