import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './user.schema';
import { Model } from 'mongoose';

@Injectable()
export class UserService {
    constructor(@InjectModel(User.name) private userModel: Model<User>,
    ) { }
    async createGoogleUser(googleData: { email: string; name: string; picture: string; provider: string }) {
        const newUser = new this.userModel({
            email: googleData.email,
            name: googleData.name,
            picture: googleData.picture,
            provider: googleData.provider,
        });

        return newUser.save();
    }
}
