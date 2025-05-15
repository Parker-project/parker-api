import { Role } from "src/common/enums/role.enum";

export class GoogleUserDto {
    email: string;
    firstName: string;
    lastName: string;
    provider: string;
    role: Role;
    isEmailVerified: boolean;
}