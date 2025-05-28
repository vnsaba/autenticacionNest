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
  HttpStatus
} from '@nestjs/common';
import { UsersService } from './users.service';
import {
    C
}
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('signup')
  signup(@Body() createUserDto) {
    return this.usersService.signup(createUserDto);
  }

  @Post('verify-email')
  verifyEmail(@Body() body: { email: string; code: string }) {
    return this.usersService.verifyEmail(body.email, body.code);
  }

  @Post('login')
  login(@Body() body: { email: string; password: string }) {
    return this.usersService.login(body.email, body.password);
  }

  @Post('refresh-token')
  refreshToken(@Body() body: { refreshToken: string }) {
    return this.usersService.refreshToken(body.refreshToken);
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

  @UseGuards(JwtAuthGuard)
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto) {
    return this.usersService.update(id, updateUserDto);
  }

  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }

  @UseGuards(JwtAuthGuard)
  @Post(':id/change-password')
  changePassword(
    @Param('id') id: string,
    @Body() body: { oldPassword: string; newPassword: string },
  ) {
    return this.usersService.changePassword(
      id,
      body.oldPassword,
      body.newPassword,
    );
  }
}
