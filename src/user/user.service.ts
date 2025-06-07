import { Injectable, NotFoundException, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './user.schema';
import { Model } from 'mongoose';
import { Role } from '../common/enums/role.enum';
import { GoogleUserDto } from './dto/googleUser.dto';
import { ReportsService } from '../reports/reports.service';

@Injectable()
export class UserService {
    private readonly logger = new Logger(UserService.name);

    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        private readonly reportsService: ReportsService
    ) { }

    async createGoogleUser(userData: GoogleUserDto) {
        this.logger.log(`Creating new Google user with email: ${userData.email}`);
        const user = await this.userModel.create({
            email: userData.email,
            firstName: userData.firstName,
            lastName: userData.lastName,
            provider: userData.provider,
            isEmailVerified: userData.isEmailVerified,
            role: Role.User,
        });
        this.logger.log(`Successfully created Google user with ID: ${user._id}`);
        return user;
    }

    async findUserByEmail(email: string) {
        this.logger.log(`Finding user by email: ${email}`);
        const user = await this.userModel.findOne({ email }).select('-password -verificationToken');
        if (!user) {
            this.logger.warn(`No user found with email: ${email}`);
        } else {
            this.logger.log(`Found user with ID: ${user._id}`);
        }
        return user;
    }

    async findAll() {
        this.logger.log('Fetching all users');
        const users = await this.userModel.find().select('-password -verificationToken -resetToken');
        this.logger.log(`Found ${users.length} users`);
        return users;
    }

    async findById(id: string) {
        this.logger.log(`Finding user by ID: ${id}`);
        const user = await this.userModel.findById(id).select('-password -verificationToken -resetToken');
        if (!user) {
            this.logger.warn(`No user found with ID: ${id}`);
            throw new NotFoundException('User not found');
        }
        this.logger.log(`Found user with ID: ${user._id}`);
        return user;
    }

    async updateRole(id: string, role: Role) {
        this.logger.log(`Updating role for user ID: ${id} to ${role}`);

        // Get the user's current role before updating
        const currentUser = await this.userModel.findById(id);
        if (!currentUser) {
            this.logger.warn(`No user found with ID: ${id} for role update`);
            throw new NotFoundException('User not found');
        }

        // If the user is currently an inspector and their role is being changed
        if (currentUser.role === Role.Inspector && role !== Role.Inspector) {
            await this.reportsService.reassignInspectorReports(id);
        }

        const updatedUser = await this.userModel.findByIdAndUpdate(
            id,
            { role },
            { new: true }
        ).select('-password -verificationToken -resetToken');

        if (!updatedUser) {
            this.logger.warn(`Failed to update user with ID: ${id}`);
            throw new NotFoundException('Failed to update user');
        }

        this.logger.log(`Successfully updated role for user ID: ${updatedUser._id}`);
        return updatedUser;
    }

    async delete(id: string) {
        this.logger.log(`Attempting to delete user with ID: ${id}`);

        // Check if the user is an inspector before deleting
        const user = await this.userModel.findById(id);
        if (!user) {
            this.logger.warn(`No user found with ID: ${id} for deletion`);
            throw new NotFoundException('User not found');
        }

        // If the user is an inspector, reassign their reports
        if (user.role === Role.Inspector) {
            await this.reportsService.reassignInspectorReports(id);
        }

        await this.userModel.findByIdAndDelete(id);
        this.logger.log(`Successfully deleted user with ID: ${id}`);
        return { message: 'User deleted successfully' };
    }

    async getUserByRole(role: Role) {
        this.logger.log(`Fetching users with role: ${role}`);
        const users = await this.userModel.find({ role }).select('-password -verificationToken -resetToken');
        this.logger.log(`Found ${users.length} users with role ${role}`);
        return users;
    }
}
