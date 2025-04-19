import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { getModelToken } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { JwtModule, JwtService } from '@nestjs/jwt';

describe('AuthService', () => {
  let service: AuthService;
  let userModel: any;
  let jwtService: JwtService

  const mockUser = {
    _id: 'userId123',
    email: 'test@example.com',
    password: 'hashedPassword',
    resetToken: undefined,
    save: jest.fn(),
  };

  const mockUserModel = {
    findOne: jest.fn(),
    find: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        JwtModule.register({
          secret: 'your-secret-key', // Provide a secret key for testing
          signOptions: { expiresIn: '1h' }, // Optional sign options
        }),
      ],
      providers: [
        AuthService,
        { provide: getModelToken('User'), useValue: mockUserModel },
        // JwtService is provided by JwtModule
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userModel = module.get(getModelToken('User'));
    jwtService = module.get<JwtService>(JwtService); // Get the JwtService instance
    jest.clearAllMocks();
  });

  // -----------------------------------------------------
  describe('sendPasswordResetEmail', () => {
    it('should not fail if user does not exist', async () => {
      mockUserModel.findOne.mockResolvedValue(null);

      const result = await service.sendPasswordResetEmail('nonexistent@example.com');
      expect(result.message).toMatch(/reset link has been sent/i);
    });

    it('should generate token and send email if user exists', async () => {
      mockUserModel.findOne.mockResolvedValue({ ...mockUser, save: jest.fn() });

      const spy = jest.spyOn<any, any>(service as any, 'sendEmail').mockResolvedValue({
        message: `Email sent to ${mockUser.email}`,
      });

      const result = await service.sendPasswordResetEmail(mockUser.email);

      expect(spy).toHaveBeenCalled();
      expect(result.message).toMatch(/reset link has been sent/i);
    });
  });

  // -----------------------------------------------------
  describe('resetPassword', () => {
    it('should throw error for invalid or expired token', async () => {
      mockUserModel.find.mockResolvedValue([]);

      await expect(service.resetPassword('badtoken', 'newPass')).rejects.toThrow(
        /invalid or expired/i,
      );
    });

    it('should reset password successfully with valid token', async () => {
      const token = 'valid-token';
      const hashedToken = await bcrypt.hash(token, 10);

      const validUser = {
        ...mockUser,
        resetToken: hashedToken,
        save: jest.fn(),
      };

      mockUserModel.find.mockResolvedValue([validUser]);

      const result = await service.resetPassword(token, 'newPass123');

      expect(validUser.save).toHaveBeenCalled();
      expect(result.message).toBe('Password reset successful');
    });
  });
});
