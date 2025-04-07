import { ConflictException, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { Model } from 'mongoose';
import { User, UserDocument } from '../user/user.schema'
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';


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
        
        return { message: 'Check your email to verify your account' };
    }
}
