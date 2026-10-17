import { IsNotEmpty, IsString } from 'class-validator';

export class DeleteSsoProviderDto {
  @IsString()
  @IsNotEmpty()
  providerId: string;
}
