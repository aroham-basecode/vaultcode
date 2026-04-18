import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { customAlphabet } from 'nanoid';
import { PrismaService } from '../prisma/prisma.service';

const nanoid32 = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 32);

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
  ) {}

  async register(email: string, password: string) {
    const normalizedEmail = email.trim().toLowerCase();

    const existing = await this.prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (existing) throw new ConflictException('Email already registered');

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await this.prisma.user.create({
      data: {
        id: nanoid32(),
        email: normalizedEmail,
        passwordHash,
      },
      select: { id: true, email: true },
    });

    const token = await this.signToken(user.id, user.email);
    return { user, token };
  }

  async login(email: string, password: string) {
    const normalizedEmail = email.trim().toLowerCase();

    const user = await this.prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) throw new UnauthorizedException('Invalid credentials');

    const token = await this.signToken(user.id, user.email);
    return { user: { id: user.id, email: user.email }, token };
  }

  private async signToken(userId: string, email: string) {
    return this.jwt.signAsync({ sub: userId, email });
  }
}
