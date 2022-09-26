import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    // hash the password
    const hash = await argon.hash(dto.password);

    // save the user to the database
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;
      // return the saved user
      return user;
    } catch (error) {
      if (
        error instanceof
        PrismaClientKnownRequestError
      ) {
        if (error.code === 'P2002') {
          throw new ForbiddenException(
            'Credentials already in use',
          );
        }
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    // find de user in the database
    const user =
      await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });
    // if user dosent exist throw an error
    if (!user) {
      throw new ForbiddenException(
        'Invalid credentials',
      );
    } else {
      // if user exists check if the password is correct
      const valid = await argon.verify(
        user.hash,
        dto.password,
      );
      // if password is incorrect throw an error
      if (!valid) {
        throw new ForbiddenException(
          'Invalid credentials',
        );
      }
      // if password is correct return the user
      delete user.hash;
      return user;
    }
  }
}
