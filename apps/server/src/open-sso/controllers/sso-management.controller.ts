import {
  Body,
  Controller,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { AuthWorkspace } from '../../common/decorators/auth-workspace.decorator';
import { AuthUser } from '../../common/decorators/auth-user.decorator';
import { User, Workspace } from '@docmost/db/types/entity.types';
import WorkspaceAbilityFactory from '../../core/casl/abilities/workspace-ability.factory';
import {
  WorkspaceCaslAction,
  WorkspaceCaslSubject,
} from '../../core/casl/interfaces/workspace-ability.type';
import { SsoProviderService } from '../services/sso-provider.service';
import { CreateSsoProviderDto } from '../dto/create-sso-provider.dto';
import { UpdateSsoProviderDto } from '../dto/update-sso-provider.dto';
import { DeleteSsoProviderDto } from '../dto/delete-sso-provider.dto';
import { SsoProviderInfoDto } from '../dto/sso-provider-info.dto';

@UseGuards(JwtAuthGuard)
@Controller('sso')
export class SsoManagementController {
  constructor(
    private readonly ssoProviderService: SsoProviderService,
    private readonly workspaceAbility: WorkspaceAbilityFactory,
  ) {}

  private checkPermission(user: User, workspace: Workspace) {
    const ability = this.workspaceAbility.createForUser(user, workspace);
    if (
      ability.cannot(WorkspaceCaslAction.Manage, WorkspaceCaslSubject.Settings)
    ) {
      throw new ForbiddenException('You do not have permission to manage SSO settings');
    }
  }

  @HttpCode(HttpStatus.OK)
  @Post('providers')
  async getProviders(
    @AuthWorkspace() workspace: Workspace,
    @AuthUser() user: User,
  ) {
    this.checkPermission(user, workspace);
    const items = await this.ssoProviderService.getProviders(workspace.id);
    return {
      items,
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('create')
  async createProvider(
    @AuthWorkspace() workspace: Workspace,
    @AuthUser() user: User,
    @Body() dto: CreateSsoProviderDto,
  ) {
    this.checkPermission(user, workspace);
    return this.ssoProviderService.createProvider(dto, workspace.id, user.id);
  }

  @HttpCode(HttpStatus.OK)
  @Post('update')
  async updateProvider(
    @AuthWorkspace() workspace: Workspace,
    @AuthUser() user: User,
    @Body() dto: UpdateSsoProviderDto,
  ) {
    this.checkPermission(user, workspace);
    return this.ssoProviderService.updateProvider(dto, workspace.id);
  }

  @HttpCode(HttpStatus.OK)
  @Post('delete')
  async deleteProvider(
    @AuthWorkspace() workspace: Workspace,
    @AuthUser() user: User,
    @Body() dto: DeleteSsoProviderDto,
  ) {
    this.checkPermission(user, workspace);
    await this.ssoProviderService.deleteProvider(dto.providerId, workspace.id);
    return { success: true };
  }

  @HttpCode(HttpStatus.OK)
  @Post('info')
  async getProviderInfo(
    @AuthWorkspace() workspace: Workspace,
    @AuthUser() user: User,
    @Body() dto: SsoProviderInfoDto,
  ) {
    this.checkPermission(user, workspace);
    if (!dto.providerId) {
      const providers = await this.ssoProviderService.getProviders(workspace.id);
      return providers[0] || null;
    }
    return this.ssoProviderService.getProviderById(dto.providerId, workspace.id);
  }
}
