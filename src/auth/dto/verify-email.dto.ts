import { ApiProperty } from "@nestjs/swagger";
import { IsString } from "class-validator";

export class VerifyEmailDto {
    @ApiProperty({ example: "726916e2ab95dcf0a4595455d80148aef3bc8a965591343df5040e8a4c4bfd43" })
    @IsString()
    verificationToken: string;
}
