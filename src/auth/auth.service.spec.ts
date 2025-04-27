import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import { getModelToken } from '@nestjs/mongoose';
import { UserService } from '../user/user.service';
import { User } from '../user/user.schema';
import * as bcrypt from 'bcrypt';

// Mocks
const mockUserModel = {
  findOne: jest.fn(),
  find: jest.fn(),
  save: jest.fn(),
  create: jest.fn()
};

const mockJwtService = {
  signAsync: jest.fn(),
};

const mockUserService = {
  createGoogleUser: jest.fn(),
};


describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: getModelToken(User.name), useValue: mockUserModel },
        { provide: JwtService, useValue: mockJwtService },
        { provide: UserService, useValue: mockUserService },
      ],
    }).compile();

    
    service = module.get<AuthService>(AuthService);

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  // SIGNUP
  describe('signup', () => {
    it('should create a user and send verification email', async () => {
        const createUserDto = {
            email: 'test@example.com',
            firstName: 'John',
            lastName: 'Doe',
            password: 'password123',
        };

        (mockUserModel.findOne as jest.Mock).mockResolvedValue(null);
        (mockUserModel.create as jest.Mock).mockResolvedValue({ ...createUserDto, _id: 'someId' }); // Mock the create method

        const sendEmailSpy = jest.spyOn(service as any, 'sendEmail').mockResolvedValue({ message: 'Email sent' });

        await service.signup(createUserDto);

        expect(mockUserModel.findOne).toHaveBeenCalledWith({ email: createUserDto.email });
        expect(mockUserModel.create).toHaveBeenCalledWith({
            email: createUserDto.email,
            firstName: createUserDto.firstName,
            lastName: createUserDto.lastName,
            password: expect.any(String), // Password is hashed, so we don't check the exact value
            verificationToken: expect.any(String), // Token is generated randomly
        });
        expect(sendEmailSpy).toHaveBeenCalled();
    });
});


  // LOGIN
  describe('login', () => {
    it('should login successfully if credentials are correct and verified', async () => {
      const userLoginDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      const user = {
        email: userLoginDto.email,
        password: await bcrypt.hash(userLoginDto.password, 10),
        isEmailVerified: true,
        _id: '123',
        role: 'user',
        firstName: 'John',
        lastName: 'Doe',
      };

      (mockUserModel.findOne as jest.Mock).mockResolvedValue(user);
      (mockJwtService.signAsync as jest.Mock).mockResolvedValue('mockAccessToken');

      const result = await service.login(userLoginDto);

      expect(result.accessToken).toBe('mockAccessToken');
      expect(result.user).toEqual(user);
    });

    it('should throw UnauthorizedException if email not found', async () => {
      (mockUserModel.findOne as jest.Mock).mockResolvedValue(null);

      await expect(
        service.login({ email: 'noexist@example.com', password: 'pass' }),
      ).rejects.toThrow('Invalid Email');
    });

    it('should throw UnauthorizedException if password is wrong', async () => {
      const user = {
        email: 'test@example.com',
        password: await bcrypt.hash('anotherpassword', 10),
        isEmailVerified: true,
      };

      (mockUserModel.findOne as jest.Mock).mockResolvedValue(user);

      await expect(
        service.login({ email: 'test@example.com', password: 'wrongpass' }),
      ).rejects.toThrow('Invalid Password');
    });

    it('should throw ForbiddenException if email not verified', async () => {
      const user = {
        email: 'test@example.com',
        password: await bcrypt.hash('password123', 10),
        isEmailVerified: false,
      };

      (mockUserModel.findOne as jest.Mock).mockResolvedValue(user);

      jest.spyOn(service, 'resendVerification').mockResolvedValue({ message: 'sent' });

      await expect(
        service.login({ email: 'test@example.com', password: 'password123' }),
      ).rejects.toThrow('Please verify your email first');
    });
  });

  // PASSWORD RESET
  describe('sendPasswordResetEmail', () => {
    it('should send reset email if user exists', async () => {
      const user = {
        email: 'test@example.com',
        save: jest.fn(),
      };

      (mockUserModel.findOne as jest.Mock).mockResolvedValue(user);

      const sendEmailSpy = jest.spyOn(service as any, 'sendEmail').mockResolvedValue({ message: 'sent' });

      const result = await service.sendPasswordResetEmail('test@example.com');

      expect(result.message).toMatch(/Reset link has been sent/i);
      expect(sendEmailSpy).toHaveBeenCalled();
    });

    it('should throw UnauthorizedException if user not found', async () => {
      (mockUserModel.findOne as jest.Mock).mockResolvedValue(null);

      await expect(service.sendPasswordResetEmail('notfound@example.com')).rejects.toThrow('Invalid Email');
    });
  });

  describe('resetPassword', () => {
    it('should reset password if token matches', async () => {
      const user = {
        email: 'test@example.com',
        resetToken: 'valid-token',
        save: jest.fn(),
      };

      (mockUserModel.findOne as jest.Mock).mockResolvedValue(user);

      const result = await service.resetPassword('valid-token', 'newpass123');

      expect(result.message).toBe('Password reset successful');
      expect(user.resetToken).toBeNull();
      expect(user.save).toHaveBeenCalled();
    });

    it('should throw BadRequestException if token is invalid', async () => {
      (mockUserModel.findOne as jest.Mock).mockResolvedValue(null);

      await expect(service.resetPassword('invalid-token', 'newpass123')).rejects.toThrow('Invalid token');
    });
  });

  // GOOGLE LOGIN
  describe('handleGoogleLogin', () => {
    it('should login an existing Google user', async () => {
      const googleUser = { email: 'google@example.com' };
      const user = { email: 'google@example.com', _id: 'abc123', role: 'user' };

      (mockUserModel.findOne as jest.Mock).mockResolvedValue(user);
      (mockJwtService.signAsync as jest.Mock).mockResolvedValue('googleToken');

      const result = await service.handleGoogleLogin(googleUser);

      expect(result.accessToken).toBe('googleToken');
    });

    it('should create a new Google user if not found', async () => {
      const googleUser = { email: 'newgoogle@example.com' };
      const newUser = { email: 'newgoogle@example.com', _id: 'new123', role: 'user' };

      (mockUserModel.findOne as jest.Mock).mockResolvedValue(null);
      (mockUserService.createGoogleUser as jest.Mock).mockResolvedValue(newUser);
      (mockJwtService.signAsync as jest.Mock).mockResolvedValue('newGoogleToken');

      const result = await service.handleGoogleLogin(googleUser);

      expect(result.accessToken).toBe('newGoogleToken');
    });
  });
});
