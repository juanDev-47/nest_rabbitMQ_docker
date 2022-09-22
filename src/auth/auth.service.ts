import { Body, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  signin(@Body() dto: AuthDto) {
    return {msg: 'I am signin'};
  }

  signup() {
    return {msg: 'I am signup'};
  }
}