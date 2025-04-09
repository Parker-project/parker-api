import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { Role } from 'src/common/enums/role.enum';

export type UserDocument = User & Document;

@Schema({timestamps:true})
export class User extends Document {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ enum: Role, default: Role.User })
  role: Role;

  @Prop({ default: false })
  isEmailVerified: boolean;

  @Prop({type: String, default: null})
  verificationToken: string | null
}

export const UserSchema = SchemaFactory.createForClass(User);
