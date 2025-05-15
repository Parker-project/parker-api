import { ApiProperty } from "@nestjs/swagger";
import { IsBoolean, IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator";
import { Role } from "src/common/enums/role.enum";

export class UserDto {
    @IsEmail()
    @ApiProperty({ example: 'john@example.com' })
    @IsEmail()
    email: string;

    @ApiProperty({ example: 'Admin' })
    role: Role;

    @ApiProperty({ example: 'John', description: 'First name of the user' })
    @IsString()
    firstName: string

    @ApiProperty({ example: 'Doe', description: 'Last name of the user' })
    @IsString()
    lastName: string

    @ApiProperty({ example: true, description: 'Whether the user has verified their email' })
    @IsBoolean()
    isEmailVerified: boolean

}
