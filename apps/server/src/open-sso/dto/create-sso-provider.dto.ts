import { IsNotEmpty, IsString, IsIn } from 'class-validator';

export class CreateSsoProviderDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsIn(['oidc', 'saml', 'google', 'ldap'])
  type: string;
}
