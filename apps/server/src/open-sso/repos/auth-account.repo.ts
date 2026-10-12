import { Injectable } from '@nestjs/common';
import { InjectKysely } from 'nestjs-kysely';
import { KyselyDB, KyselyTransaction } from '@docmost/db/types/kysely.types';
import { dbOrTx } from '@docmost/db/utils';
import { AuthAccounts } from '@docmost/db/types/db';
import { Insertable, Selectable } from 'kysely';

export type AuthAccount = Selectable<AuthAccounts>;
export type InsertableAuthAccount = Insertable<AuthAccounts>;

@Injectable()
export class AuthAccountRepo {
  public baseFields: Array<keyof AuthAccounts> = [
    'id',
    'userId',
    'providerUserId',
    'authProviderId',
    'workspaceId',
    'createdAt',
    'updatedAt',
    'deletedAt',
  ];

  constructor(@InjectKysely() private readonly db: KyselyDB) {}

  async findByProviderUserId(
    providerUserId: string,
    authProviderId: string,
    opts?: { trx?: KyselyTransaction },
  ): Promise<AuthAccount | undefined> {
    const db = dbOrTx(this.db, opts?.trx);
    return db
      .selectFrom('authAccounts')
      .select(this.baseFields)
      .where('providerUserId', '=', providerUserId)
      .where('authProviderId', '=', authProviderId)
      .where('deletedAt', 'is', null)
      .executeTakeFirst();
  }

  async findByUserIdAndProvider(
    userId: string,
    authProviderId: string,
    opts?: { trx?: KyselyTransaction },
  ): Promise<AuthAccount | undefined> {
    const db = dbOrTx(this.db, opts?.trx);
    return db
      .selectFrom('authAccounts')
      .select(this.baseFields)
      .where('userId', '=', userId)
      .where('authProviderId', '=', authProviderId)
      .where('deletedAt', 'is', null)
      .executeTakeFirst();
  }

  async insertAccount(
    data: InsertableAuthAccount,
    trx?: KyselyTransaction,
  ): Promise<AuthAccount> {
    const db = dbOrTx(this.db, trx);
    return db
      .insertInto('authAccounts')
      .values({
        ...data,
        createdAt: new Date(),
        updatedAt: new Date(),
      })
      .returning(this.baseFields)
      .executeTakeFirstOrThrow();
  }
}
