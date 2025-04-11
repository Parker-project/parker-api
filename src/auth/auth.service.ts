import { BadRequestException, ConflictException, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { Model } from 'mongoose';
import { User, UserDocument } from '../user/user.schema'
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import * as nodemailer from 'nodemailer';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { UserLoginDto } from './dto/user-login.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<UserDocument>,
        private jwtService: JwtService
    ) { }
    async signup(createUserDto: CreateUserDto) {
        const existingUser = await this.userModel.findOne({ email: createUserDto.email })
        if (existingUser) {
            throw new ConflictException('Email address is already in use')
        }

        const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
        const verificationToken = this.generateVerificationToken();

        const user = new this.userModel({
            ...createUserDto,
            password: hashedPassword,
            verificationToken
        })
        await user.save()

        // Send Email verification 
        await this.sendVerificationEmail(createUserDto.email, verificationToken)
    }

    private async sendVerificationEmail(to: string, token: string): Promise<{ message: string }> {
        const transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: Number(process.env.SMTP_PORT),
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS,
            },
        });

        const url = `${process.env.FRONTEND_URL}/verify-email?token=${token}`

        await transporter.sendMail({
            from: process.env.FROM_EMAIL,
            to,
            subject: 'Verify your Parker App Account',
            html: `<p>Click <a href="${url}">here</a> to verify your email.</p>`,
        })

        return { message: 'Check your email to verify your account' };
    }

    async verifyEmail(verifyEmailDto: VerifyEmailDto) {
        const user = await this.userModel.findOne({ verificationToken: verifyEmailDto.verificationToken })

        if (!user) {
            throw new BadRequestException('Invalid verification token');
        }

        user.isEmailVerified = true;
        user.verificationToken = null

        await user.save()

        return { message: "Your email is verified", user };
    }

    async resendVerification(email: string) {
        const user = await this.userModel.findOne({ email })
        if (!user) {
            throw new BadRequestException('User not found');
        }
        if (user.isEmailVerified) {
            throw new BadRequestException('Email already verified');
        }

        const newToken = this.generateVerificationToken();
        user.verificationToken = newToken;
        await user.save()

        return this.sendVerificationEmail(email, newToken)
    }

    async login(userLoginDto: UserLoginDto) {
        const user = await this.userModel.findOne({ email: userLoginDto.email });
        if (!user) throw new UnauthorizedException('Invalid Email');

        const isPasswordMatch = await bcrypt.compare(userLoginDto.password, user.password);
        if (!isPasswordMatch) throw new UnauthorizedException('Invalid Password');

        if (!user.isEmailVerified) {
            this.resendVerification(userLoginDto.email)
            throw new ForbiddenException('Please verify your email first');
        }

        const payload = { sub: user._id, role: user.role };
        const accessToken = await this.jwtService.signAsync(payload);

        return { accessToken , user };
    }

    private generateVerificationToken(): string {
        return randomBytes(32).toString('hex');
    }


}
