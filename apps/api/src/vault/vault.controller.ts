import { Body, Controller, Get, Put, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { VaultService } from './vault.service';

type AuthedRequest = {
  user: {
    userId: string;
    email: string;
  };
};

@Controller('vault')
export class VaultController {
  constructor(private readonly vaults: VaultService) {}

  @UseGuards(JwtAuthGuard)
  @Get()
  async getVault(@Req() req: AuthedRequest) {
    return this.vaults.getVault(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Put()
  async putVault(
    @Req() req: AuthedRequest,
    @Body() body: { encryptedVault: unknown; version?: number },
  ) {
    return this.vaults.upsertVault(req.user.userId, body.encryptedVault, body.version);
  }
}
