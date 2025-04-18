import { ApiProperty } from "@nestjs/swagger";
import { IsEmail } from "class-validator";

export class MailDto {
    @ApiProperty({ example: 'john@example.com', description: 'User email address' })
    @IsEmail()
    email: string
}
