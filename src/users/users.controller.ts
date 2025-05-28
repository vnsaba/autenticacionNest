import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { UsersService } from './users.service';
import {
  CreateUserDto,
  UpdateUserDto,
  LoginDto,
  RefreshTokenDto,
  ChangePasswordDto,
  VerifyEmailDto,
} from './dto/user.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('signup')
  async create(@Body() createUserDto: CreateUserDto) {
    await this.usersService.create(createUserDto);
    return {
      message:
        'User registered successfully. Please check your email for verification code.',
    };
  }

  @Post('verify-email')
  verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
    return this.usersService.verifyEmail(verifyEmailDto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('login')
  login(@Body() loginDto: LoginDto) {
    return this.usersService.login(loginDto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('refresh-token')
  refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.usersService.refreshToken(refreshTokenDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  findAll() {
    return this.usersService.findAll();
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(id, updateUserDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }

  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  changePassword(@Body() changePasswordDto: ChangePasswordDto) {
    return this.usersService.changePassword(changePasswordDto);
  }
}
