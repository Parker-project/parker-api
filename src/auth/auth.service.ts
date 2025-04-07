import { Injectable } from '@nestjs/common';
import { createUser } from 'src/user/dto/create-user/create-user.dto';

@Injectable()
export class AuthService {
    signup(createUserDTO: createUser) {
        return;
    }
}
