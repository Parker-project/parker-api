import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class CreateUserDto {
    @ApiProperty({ example: 'john@example.com', description: 'User email address' })
    @IsEmail()
    email: string;
    
    @ApiProperty({ example: 'P!@assword123', description: 'User password' })
    @IsNotEmpty()
    @MinLength(6)
    password: string;

    @ApiProperty({ example: 'John', description: 'First name of the user' })
    @IsString()
    firstName:string
    
    @ApiProperty({ example: 'Doe', description: 'Last name of the user' })
    @IsString()
    lastName:string
}
