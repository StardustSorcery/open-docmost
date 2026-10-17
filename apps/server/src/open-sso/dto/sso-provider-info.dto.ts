import { IsOptional, IsString } from 'class-validator';

export class SsoProviderInfoDto {
  @IsString()
  @IsOptional()
  providerId?: string;
}
