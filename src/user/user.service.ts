import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './user.schema';
import { Model } from 'mongoose';
import { Role } from '../common/enums/role.enum';
import { GoogleUserDto } from './dto/googleUser.dto';

@Injectable()
export class UserService {
    constructor(@InjectModel(User.name) private userModel: Model<User>,
    ) { }
    async createGoogleUser(userData: GoogleUserDto) {
        return this.userModel.create({
            email: userData.email,
            firstName: userData.firstName,
            lastName: userData.lastName,
            provider: userData.provider,
            isEmailVerified: userData.isEmailVerified,
            role: Role.User, 
        });
    }

    async findUserByEmail(email: string) {
        return this.userModel.findOne({ email }).select('-password -verificationToken');
    }
}
