import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';

import { User as SchemaUser, UserDocument } from './schemas/user.schema';
import {
  ChangePasswordDto,
  CreateUserDto,
  LoginDto,
  RefreshTokenDto,
  UpdateUserDto,
  VerifyEmailDto,
} from './dto/user.dto';
import { EmailService } from '../email/email.service';
import { User, UserServiceInterface } from './interfaces/user.interface';

@Injectable()
export class UsersService implements UserServiceInterface {
  constructor(
    @InjectModel(SchemaUser.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private emailService: EmailService,
  ) {}
  findAll(): Promise<User[]> {
    throw new Error('Method not implemented.');
  }
  findOne(id: string): Promise<User> {
    throw new Error('Method not implemented.');
  }
  findByEmail(email: string): Promise<User> {
    throw new Error('Method not implemented.');
  }
  update(id: string, updateUserDto: SchemaUser): Promise<User> {
    throw new Error('Method not implemented.');
  }
  remove(id: string): Promise<void> {
    throw new Error('Method not implemented.');
  }
  verifyUser(id: string): Promise<User> {
    throw new Error('Method not implemented.');
  }
  login(loginDto: SchemaUser): Promise<{ accessToken: string; refreshToken: string; user: User; }> {
    throw new Error('Method not implemented.');
  }
  refreshToken(refreshToken: string): Promise<{ accessToken: string; refreshToken: string; }> {
    throw new Error('Method not implemented.');
  }
  changePassword(id: string, changePasswordDto: SchemaUser): Promise<void> {
    throw new Error('Method not implemented.');
  }

  private toUserInterface(userDoc: UserDocument): User {
    const userObj = userDoc.toObject();
    userObj.id = userObj._id.toString();
    delete userObj.password;
    delete userObj.__v;
    return userObj as User;
  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    // Check if user already exists
    const existingUser = await this.userModel
      .findOne({ email: createUserDto.email })
      .exec();
    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    // Generate verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const verificationCodeExpires = new Date();
    verificationCodeExpires.setMinutes(verificationCodeExpires.getMinutes() + 5);
    return this.userModel
      .create({
        ...createUserDto,
        password: hashedPassword,
        isVerified: false,
        verificationCode,
        verificationCodeExpires,
      })
      .then((userDoc) => {
        // Send verification email
        this.emailService.sendVerificationEmail(
          userDoc.email,
          userDoc.firstName,
          verificationCode,
        );
        return this.toUserInterface(userDoc);
      }
      )
      .catch((error) => {
        if (error.code === 11000) {
          throw new ConflictException('Email already registered');
        }
        throw new BadRequestException('Error creating user');
      }
      );
  }
}