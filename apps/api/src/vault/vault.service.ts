import { Injectable } from '@nestjs/common';
import { customAlphabet } from 'nanoid';
import { PrismaService } from '../prisma/prisma.service';

const nanoid32 = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 32);

@Injectable()
export class VaultService {
  constructor(private readonly prisma: PrismaService) {}

  async getVault(userId: string) {
    const vault = await this.prisma.vault.findUnique({
      where: { userId },
      select: {
        encryptedVault: true,
        version: true,
        updatedAt: true,
        createdAt: true,
      },
    });
    return vault;
  }

  async upsertVault(userId: string, encryptedVault: unknown, version?: number) {
    return this.prisma.vault.upsert({
      where: { userId },
      create: {
        id: nanoid32(),
        userId,
        encryptedVault: encryptedVault as any,
        version: version ?? 1,
      },
      update: {
        encryptedVault: encryptedVault as any,
        version: version ?? undefined,
      },
      select: {
        encryptedVault: true,
        version: true,
        updatedAt: true,
        createdAt: true,
      },
    });
  }
}
