import { ApiProperty } from "@nestjs/swagger";
import { IsBoolean, IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator";

export class UserLoginDto {
    @IsEmail()
    @ApiProperty({ example: 'john@example.com' })
    @IsEmail()
    email: string;

    @ApiProperty({ example: 'password123' })
    @IsNotEmpty()
    password: string;

    @ApiProperty({ default: false, required: false })
    @IsOptional()
    rememberMe?: boolean;
}
