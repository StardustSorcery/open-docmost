import {
  IsBoolean,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUrl,
} from 'class-validator';

export class UpdateSsoProviderDto {
  @IsString()
  @IsNotEmpty()
  providerId: string;

  @IsString()
  @IsOptional()
  name?: string;

  @IsUrl()
  @IsOptional()
  oidcIssuer?: string;

  @IsString()
  @IsOptional()
  oidcClientId?: string;

  @IsString()
  @IsOptional()
  oidcClientSecret?: string;

  @IsBoolean()
  @IsOptional()
  isEnabled?: boolean;

  @IsBoolean()
  @IsOptional()
  allowSignup?: boolean;

  @IsBoolean()
  @IsOptional()
  groupSync?: boolean;
}
