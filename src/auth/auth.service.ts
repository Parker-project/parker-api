import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import * as nodemailer from 'nodemailer';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';

import { CreateUserDto } from './dto/create-user.dto';
import { User, UserDocument } from '../user/user.schema'
import { VerifyEmailDto } from './dto/verify-email.dto';
import { UserLoginDto } from './dto/user-login.dto';
import { UserService } from '../user/user.service';
import { EmailOptions } from '../common/interfaces/email-options.interface';
import { Role } from 'src/common/enums/role.enum';

@Injectable()
export class AuthService {
    private readonly transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT),
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        },
    })
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        private readonly jwtService: JwtService,
        private readonly userService: UserService,
        @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: Logger) { }
    async signup(createUserDto: CreateUserDto) {
        this.logger.log(`Attempting to register user: ${createUserDto.email}`, 'AuthService');

        try {
            const existingUser = await this.userModel.findOne({ email: createUserDto.email })
            if (existingUser) {
                this.logger.warn(`Registration failed: Email already exists: ${createUserDto.email}`, 'AuthService');
                throw new ConflictException('Email address is already in use')
            }

            const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
            const verificationToken = this.generateToken();
            const { email, firstName, lastName } = createUserDto

            await this.userModel.create({
                firstName,
                lastName,
                email,
                password: hashedPassword,
                verificationToken
            })

            this.logger.log(`User registered successfully: ${email}`, 'AuthService');

            // Send Email verification
            await this.sendEmail({
                to: createUserDto.email,
                subject: 'Verify your Parker App Account',
                html: `<p>Click <a href="${process.env.BACKEND_URL}/auth/verify-email/${verificationToken}">here</a> to verify your email.</p>`,
            });
            return { message: 'Registration successful. Please check your email to verify your account.' };
        } catch (error) {
            this.logger.error(`Error creating user: ${error.message}`, undefined, 'AuthService');
            throw error;
        }
    }

    async verifyEmailDirect(verificationToken: string) {
        this.logger.log(`Directly verifying email with token: ${verificationToken.substring(0, 8)}...`, 'AuthService');

        try {
            const user = await this.userModel.findOne({ verificationToken });

            if (!user) {
                this.logger.warn(`Invalid verification token: ${verificationToken.substring(0, 8)}...`, 'AuthService');
                throw new BadRequestException('Invalid verification token');
            }

            user.isEmailVerified = true;
            user.verificationToken = null;

            await user.save();

            this.logger.log(`Email verified successfully for user: ${user.email}`, 'AuthService');

            return { message: "Your email is verified", user };
        } catch (error) {
            this.logger.error(`Error directly verifying email: ${error.message}`, undefined, 'AuthService');
            throw error;
        }
    }

    async resendVerification(email: string) {
        this.logger.log(`Resending verification email to: ${email}`, 'AuthService');

        try {
            const user = await this.userModel.findOne({ email })

            if (!user) {
                this.logger.warn(`User not found for resend verification: ${email}`, 'AuthService');
                throw new BadRequestException('User not found');
            }
            if (user.isEmailVerified) {
                this.logger.warn(`Email already verified for user: ${email}`, 'AuthService');
                throw new BadRequestException('Email already verified');
            }

            const newToken = this.generateToken();
            user.verificationToken = newToken;
            await user.save()

            this.logger.log(`Verification token updated for user: ${email}`, 'AuthService');

            return await this.sendEmail({
                to: email,
                subject: 'Verify your Parker App Account',
                html: `<p>Click <a href="${process.env.BACKEND_URL}/auth/verify-email/${newToken}">here</a> to verify your email.</p>`,
            });
        } catch (error) {
            this.logger.error(`Error resending verification: ${error.message}`, undefined, 'AuthService');
            throw error;
        }
    }

    async login(userLoginDto: UserLoginDto) {
        this.logger.log(`Login attempt for user: ${userLoginDto.email}`, 'AuthService');

        try {
            const user = await this.userModel.findOne({ email: userLoginDto.email });

            if (!user) {
                this.logger.warn(`Login failed: User not found: ${userLoginDto.email}`, 'AuthService');
                throw new UnauthorizedException('Invalid Email');
            }

            const isPasswordMatch = await bcrypt.compare(userLoginDto.password, user.password);
            if (!isPasswordMatch) {
                this.logger.warn(`Login failed: Invalid password for user: ${userLoginDto.email}`, 'AuthService');
                throw new UnauthorizedException('Invalid Password');
            }

            if (!user.isEmailVerified) {
                this.logger.warn(`Login failed: Email not verified for user: ${userLoginDto.email}`, 'AuthService');
                this.resendVerification(userLoginDto.email)
                throw new ForbiddenException('Please verify your email first');
            }

            const sanitizedUser = {
                email: user.email,
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                role: user.role,
                isEmailVerified: user.isEmailVerified
            };

            const payload = {
                sub: user.id,
                email: user.email,
                role: user.role,
                firstName: user.firstName,
                isEmailVerified: user.isEmailVerified
            };
            const accessToken = await this.jwtService.signAsync(payload);

            this.logger.log(`User logged in successfully: ${userLoginDto.email}`, 'AuthService');

            return { accessToken, sanitizedUser };
        } catch (error) {
            this.logger.error(`Error during login: ${error.message}`, undefined, 'AuthService');
            throw error;
        }
    }

    private generateToken(): string {
        return randomBytes(32).toString('hex');
    }

    async handleGoogleLogin(googleUser: any) {
        this.logger.log(`Google login attempt for: ${googleUser.email}`, 'AuthService');

        try {
            let user = await this.userModel.findOne({ email: googleUser.email }).exec();

            if (!user) {
                this.logger.log(`Creating new Google user: ${googleUser.email}`, 'AuthService');
                user = await this.userService.createGoogleUser({
                    email: googleUser.email,
                    firstName: googleUser.given_name || googleUser.name,
                    lastName: googleUser.family_name || '',
                    provider: 'google',
                    role: Role.User, // Default role
                    isEmailVerified: true, // Google emails are verified
                });
            }
            else {
                user.isEmailVerified = true;
                await user.save();
            }

            // Match the same sanitized user structure as regular login
            const sanitizedUser = {
                email: user.email,
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                role: user.role,
                isEmailVerified: user.isEmailVerified
            };

            // Match the same payload structure as regular login
            const payload = {
                sub: user.id,
                email: user.email,
                role: user.role,
                firstName: user.firstName,
                isEmailVerified: user.isEmailVerified,
            };
            const accessToken = await this.jwtService.signAsync(payload);

            this.logger.log(`Google user logged in successfully: ${googleUser.email}`, 'AuthService');

            return { accessToken, sanitizedUser };
        } catch (error) {
            this.logger.error(`Error during Google login: ${error.message}`, undefined, 'AuthService');
            throw error;
        }
    }

    async sendPasswordResetEmail(email: string) {
        this.logger.log(`Password reset requested for: ${email}`, 'AuthService');
        try {
            const user = await this.userModel.findOne({ email });
            if (!user) {
                this.logger.warn(`Password reset failed: User not found: ${email}`, 'AuthService');
                throw new UnauthorizedException('Invalid Email');
            }

            const token = this.generateToken()
            user.resetToken = token;
            await user.save();

            const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
            this.sendEmail({
                to: email,
                subject: 'Password Reset for Parker App',
                html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>
                <p>This link will expire in a short period of time.</p>`,
            });

            this.logger.log(`Password reset email sent to: ${email}`, 'AuthService');
            return { message: 'Reset link has been sent.' };
        }
        catch (error) {
            this.logger.error(`Error sending password reset email: ${error.message}`, undefined, 'AuthService');
            throw error;
        }
    }

    private async sendEmail(options: EmailOptions): Promise<{ message: string }> {
        this.logger.log(`Sending email to: ${options.to}`, 'AuthService');
        try {
            await this.transporter.sendMail({
                from: process.env.FROM_EMAIL,
                ...options,
            });
            this.logger.log(`Email sent successfully to: ${options.to}`, 'AuthService');
            return { message: `Email sent to ${options.to}` };
        } catch (error) {
            this.logger.error(`Error sending email to ${options.to}: ${error.message}`, undefined, 'AuthService');
            throw new BadRequestException(`Failed to send email to ${options.to}`);
        }
    }

    async resetPassword(token: string, password: string) {
        this.logger.log(`Password reset attempt with token: ${token?.substring(0, 8)}...`, 'AuthService');
        try {
            if (!token || !password) {
                this.logger.warn('Password reset failed: Missing token or new password', 'AuthService');
                throw new BadRequestException('Token and new password are required');
            }

            const user = await this.userModel.findOne({ resetToken: token });
            if (!user) {
                this.logger.warn(`Password reset failed: Invalid token: ${token.substring(0, 8)}...`, 'AuthService');
                throw new BadRequestException('Invalid token');
            }

            user.password = await bcrypt.hash(password, 10);
            user.resetToken = null;
            await user.save();

            this.logger.log(`Password reset successful for user: ${user.email}`, 'AuthService');
            return { message: 'Password reset successful' };
        }
        catch (error) {
            this.logger.error(`Error resetting password: ${error.message}`, undefined, 'AuthService');
            throw error;
        }
    }

}
