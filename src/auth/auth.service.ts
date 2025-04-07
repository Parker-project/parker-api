import { BadRequestException, ConflictException, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { Model } from 'mongoose';
import { User, UserDocument } from '../user/user.schema'
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import * as nodemailer from 'nodemailer';
import { VerifyEmailDto } from './dto/verify-email.dto';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<UserDocument>
    ) { }
    async signup(createUserDto: CreateUserDto): Promise<{ message: string }> {
        const existingUser = await this.userModel.findOne({ email: createUserDto.email })
        console.log("🚀 ~ AuthService ~ signup ~ existingUser:", existingUser)
        if (existingUser) {
            throw new ConflictException('Email address is already in use')
        }

        const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
        const verificationToken = randomBytes(32).toString('hex');

        const user = new this.userModel({
            ...createUserDto,
            password: hashedPassword,
            verificationToken
        })
        await user.save()

        // Send Email verification 
        await this.sendVerificationEmail(createUserDto.email, verificationToken)

        return { message: 'Check your email to verify your account' };
    }

    private async sendVerificationEmail(to: string, token: string) {
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
    }

    async verifyEmail(verifyEmailDto: VerifyEmailDto) {
        const user = await this.userModel.findOne({ verificationToken: verifyEmailDto.verificationToken })

        if (!user) {
            throw new BadRequestException('Invalid verification token');
        }

        user.isEmailVerified = true;
        user.verificationToken = null

        await user.save()

        return user;
    }
}
