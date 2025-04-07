import { Body, Controller, Patch, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('signup')
    signup(@Body() createUserDTO: CreateUserDto) {
        return this.authService.signup(createUserDTO)
    }

    @Patch('verify-email')
    verifyEmail(@Body() verificationToken: string) {
        return this.authService.verifyEmail(verificationToken)
    }
}
