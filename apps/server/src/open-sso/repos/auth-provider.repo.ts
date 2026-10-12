import { Injectable } from '@nestjs/common';
import { InjectKysely } from 'nestjs-kysely';
import { KyselyDB, KyselyTransaction } from '@docmost/db/types/kysely.types';
import { dbOrTx } from '@docmost/db/utils';
import { AuthProviders } from '@docmost/db/types/db';
import {
  AuthProvider,
  InsertableAuthProvider,
  UpdatableAuthProvider,
} from '@docmost/db/types/entity.types';

@Injectable()
export class AuthProviderRepo {
  public baseFields: Array<keyof AuthProviders> = [
    'id',
    'name',
    'type',
    'oidcIssuer',
    'oidcClientId',
    'oidcClientSecret',
    'samlUrl',
    'samlCertificate',
    'allowSignup',
    'isEnabled',
    'groupSync',
    'creatorId',
    'workspaceId',
    'createdAt',
    'updatedAt',
    'deletedAt',
  ];

  constructor(@InjectKysely() private readonly db: KyselyDB) {}

  async findById(
    providerId: string,
    workspaceId: string,
    opts?: { trx?: KyselyTransaction },
  ): Promise<AuthProvider | undefined> {
    const db = dbOrTx(this.db, opts?.trx);
    return db
      .selectFrom('authProviders')
      .select(this.baseFields)
      .where('id', '=', providerId)
      .where('workspaceId', '=', workspaceId)
      .where('deletedAt', 'is', null)
      .executeTakeFirst();
  }

  async findEnabledById(
    providerId: string,
    opts?: { trx?: KyselyTransaction },
  ): Promise<AuthProvider | undefined> {
    const db = dbOrTx(this.db, opts?.trx);
    return db
      .selectFrom('authProviders')
      .select(this.baseFields)
      .where('id', '=', providerId)
      .where('isEnabled', '=', true)
      .where('deletedAt', 'is', null)
      .executeTakeFirst();
  }

  async findByWorkspaceId(
    workspaceId: string,
    opts?: { trx?: KyselyTransaction },
  ): Promise<AuthProvider[]> {
    const db = dbOrTx(this.db, opts?.trx);
    return db
      .selectFrom('authProviders')
      .select(this.baseFields)
      .where('workspaceId', '=', workspaceId)
      .where('deletedAt', 'is', null)
      .orderBy('createdAt', 'asc')
      .execute();
  }

  async findFirstByType(
    type: string,
    workspaceId: string,
    opts?: { trx?: KyselyTransaction },
  ): Promise<AuthProvider | undefined> {
    const db = dbOrTx(this.db, opts?.trx);
    return db
      .selectFrom('authProviders')
      .select(this.baseFields)
      .where('type', '=', type)
      .where('workspaceId', '=', workspaceId)
      .where('deletedAt', 'is', null)
      .executeTakeFirst();
  }

  async insertProvider(
    data: InsertableAuthProvider,
    trx?: KyselyTransaction,
  ): Promise<AuthProvider> {
    const db = dbOrTx(this.db, trx);
    return db
      .insertInto('authProviders')
      .values({
        ...data,
        createdAt: new Date(),
        updatedAt: new Date(),
      })
      .returning(this.baseFields)
      .executeTakeFirstOrThrow();
  }

  async updateProvider(
    data: UpdatableAuthProvider,
    providerId: string,
    workspaceId: string,
    trx?: KyselyTransaction,
  ): Promise<AuthProvider | undefined> {
    const db = dbOrTx(this.db, trx);
    return db
      .updateTable('authProviders')
      .set({
        ...data,
        updatedAt: new Date(),
      })
      .where('id', '=', providerId)
      .where('workspaceId', '=', workspaceId)
      .returning(this.baseFields)
      .executeTakeFirst();
  }

  async softDeleteProvider(
    providerId: string,
    workspaceId: string,
    trx?: KyselyTransaction,
  ): Promise<boolean> {
    const db = dbOrTx(this.db, trx);
    const result = await db
      .updateTable('authProviders')
      .set({
        deletedAt: new Date(),
        isEnabled: false,
        updatedAt: new Date(),
      })
      .where('id', '=', providerId)
      .where('workspaceId', '=', workspaceId)
      .execute();

    return Number(result[0]?.numUpdatedRows ?? 0) > 0;
  }
}
