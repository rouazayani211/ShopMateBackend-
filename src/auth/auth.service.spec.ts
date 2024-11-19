import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import { getModelToken } from '@nestjs/mongoose';  // For mocking Mongoose model
import { User } from '../user/shemas/user.schema';
import { UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';

describe('AuthService', () => {
  let authService: AuthService;
  let userService: UserService;
  let mockUserModel;

  beforeEach(async () => {
    mockUserModel = {
      findOne: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        UserService,
        JwtService,
        {
          provide: getModelToken(User.name),
          useValue: mockUserModel,
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    userService = module.get<UserService>(UserService);
  });

  it('should be defined', () => {
    expect(authService).toBeDefined();
  });

  describe('validateGoogleUser', () => {
    it('should return a user if it already exists', async () => {
      const googleUser = {
        googleId: 'google123',
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
      };

      // Mock the behavior of the model's findOne method to return an existing user
      const mockUser = {
        _id: 'someUserId',
        email: googleUser.email,
        googleId: googleUser.googleId,
        nom: googleUser.lastName,
        prenom: googleUser.firstName,
      };
      mockUserModel.findOne.mockResolvedValue(mockUser);

      const user = await authService.validateGoogleUser(
        googleUser.googleId,
        googleUser.firstName,
        googleUser.lastName,
        googleUser.email,
      );

      expect(user).toEqual(mockUser);
      expect(mockUserModel.findOne).toHaveBeenCalledWith({ email: googleUser.email });
    });

    it('should create a new user if not found in the database', async () => {
      const googleUser = {
        googleId: 'google123',
        firstName: 'Jane',
        lastName: 'Doe',
        email: 'jane.doe@example.com',
      };

      // Mock the behavior of the model's findOne method to return null (user not found)
      mockUserModel.findOne.mockResolvedValue(null);

      // Mock the create method
      const newUser = {
        email: googleUser.email,
        googleId: googleUser.googleId,
        nom: googleUser.lastName,
        prenom: googleUser.firstName,
      };
      mockUserModel.create.mockResolvedValue(newUser);

      const user = await authService.validateGoogleUser(
        googleUser.googleId,
        googleUser.firstName,
        googleUser.lastName,
        googleUser.email,
      );

      expect(user).toEqual(newUser);
      expect(mockUserModel.findOne).toHaveBeenCalledWith({ email: googleUser.email });
      expect(mockUserModel.create).toHaveBeenCalledWith({
        email: googleUser.email,
        googleId: googleUser.googleId,
        nom: googleUser.lastName,
        prenom: googleUser.firstName,
      });
    });
  });
});
