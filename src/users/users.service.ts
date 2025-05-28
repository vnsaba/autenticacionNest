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
import * as bcrypt from 'bcrypt';
import { User as SchemaUser, UserDocument } from './schemas/user.schema';
import {
  CreateUserDto,
  LoginDto,
  VerifyEmailDto,
  RefreshTokenDto,
  UpdateUserDto,
  ChangePasswordDto,
} from './dto/user.dto';
import { EmailService } from '../email/email.service';
import { User } from './interfaces/user.interface';
import { Model } from 'mongoose';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(SchemaUser.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private emailService: EmailService,
  ) {}

  private toUserInterface(userDoc: UserDocument): User {
    const userObj = userDoc.toObject();
    userObj.id = userObj._id.toString();
    delete userObj.password;
    delete userObj.__v;
    return userObj as User;
  }

  // 1. Registro de Usuario
  async create(createUserDto: CreateUserDto): Promise<User> {
    // Check if user already exists
    const existingUser = await this.userModel
      .findOne({ email: createUserDto.email })
      .exec();
    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    // hash the password
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    // Generate verification code and expiration
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000,
    ).toString();
    const verificationCodeExpires = new Date();
    verificationCodeExpires.setMinutes(
      verificationCodeExpires.getMinutes() + 5,
    );

    const newUser = new this.userModel({
      ...createUserDto,
      password: hashedPassword,
      isVerified: false,
      verificationCode,
      verificationCodeExpires,
    });

    await newUser.save();

    await this.emailService.sendVerificationEmail(
      createUserDto.email,
      createUserDto.firstName,
      verificationCode,
    );

    return this.toUserInterface(newUser);
  }

  // 2. Verificación del Email
  async verifyEmail(verifyEmailDto: VerifyEmailDto): Promise<User> {
    const { email, code } = verifyEmailDto;

    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.verificationCode !== code) {
      throw new BadRequestException('Invalid verification code');
    }

    if (user.verificationCodeExpires < new Date()) {
      throw new BadRequestException('Verification code has expired');
    }

    user.isVerified = true;
    user.verificationCode = undefined;
    user.verificationCodeExpires = undefined;

    await user.save();

    return this.toUserInterface(user);
  }

  // 3. Inicio de Sesión
  async login(
    loginDto: LoginDto,
  ): Promise<{ accessToken: string; refreshToken: string; user: User }> {
    const { email, password } = loginDto;

    // Verifica si el usuario existe
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Valida la contraseña
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Verifica si el usuario está verificado
    if (!user.isVerified) {
      throw new UnauthorizedException('User is not verified');
    }

    // Genera el access token
    const payload = { sub: user._id, email: user.email };
    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
      expiresIn: this.configService.get<string>('JWT_ACCESS_EXPIRATION'),
    });

    // Genera el refresh token
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION'),
    });

    // Hashea el refresh token y lo guarda en la base de datos
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    user.hashedRefreshToken = hashedRefreshToken;
    await user.save();

    return {
      accessToken,
      refreshToken,
      user: this.toUserInterface(user),
    };
  }

  async refreshToken(
    refreshTokenDto: RefreshTokenDto,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const { refreshToken } = refreshTokenDto;

    const payload = this.jwtService.verify(refreshToken, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
    });

    const user = await this.userModel.findById(payload.sub).exec();
    if (!user || !user.hashedRefreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const isRefreshTokenValid = await bcrypt.compare(
      refreshToken,
      user.hashedRefreshToken,
    );
    if (!isRefreshTokenValid) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const newPayload = { sub: user._id, email: user.email };
    const newAccessToken = this.jwtService.sign(newPayload, {
      secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
      expiresIn: this.configService.get<string>('JWT_ACCESS_EXPIRATION'),
    });

    const newRefreshToken = this.jwtService.sign(newPayload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION'),
    });

    const hashedNewRefreshToken = await bcrypt.hash(newRefreshToken, 10);
    user.hashedRefreshToken = hashedNewRefreshToken;
    await user.save();

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }

  async findAll(): Promise<User[]> {
    try {
      const users = await this.userModel.find().exec();
      return users.map(this.toUserInterface);
    } catch (error) {
      throw new BadRequestException('Error fetching users');
    }
  }

  findOne(id: string): Promise<User> {
    return this.userModel
      .findById(id)
      .exec()
      .then((user) => {
        if (!user) {
          throw new NotFoundException('User not found');
        }
        return this.toUserInterface(user);
      });
  }

  async findByEmail(email: string): Promise<User> {
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return this.toUserInterface(user);
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const user = await this.userModel
      .findByIdAndUpdate(
        id,
        { $set: updateUserDto },
        { new: true, runValidators: true },
      )
      .exec();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.toUserInterface(user);
  }

  async remove(id: string): Promise<void> {
    const result = await this.userModel.findByIdAndDelete(id).exec();
    if (!result) {
      throw new NotFoundException('User not found');
    }
  }

  async verifyUser(id: string): Promise<User> {
    const user = await this.userModel.findById(id).exec();
    if (!user) {
      throw new NotFoundException('User not found');
    }
    user.isVerified = true;
    user.verificationCode = undefined;
    user.verificationCodeExpires = undefined;
    await user.save();
    return this.toUserInterface(user);
  }

  async changePassword(changePasswordDto: ChangePasswordDto): Promise<void> {
    const { email, currentPassword, newPassword } = changePasswordDto;
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      throw new NotFoundException('User not found');
    }
    const isPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid current password');
    }
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
  }
}
