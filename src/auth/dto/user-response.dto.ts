import { IsBoolean, IsEmail, IsString } from "class-validator";

export class UserResponseDto {
    @IsString()
    id: string;
    @IsEmail()
    email: string;
    @IsBoolean()
    isEmailVerified: boolean;
}
