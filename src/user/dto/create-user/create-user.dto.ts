import { IsNotEmpty, IsEmail, MinLength } from 'class-validator';

export class createUser {
    @IsNotEmpty()
    @IsEmail()
    email: string;

    @IsNotEmpty()
    @MinLength(6)
    password: string;  


}
