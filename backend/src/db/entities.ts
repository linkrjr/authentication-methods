import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  ManyToOne,
  PrimaryColumn,
  PrimaryGeneratedColumn,
  Unique,
  UpdateDateColumn,
} from "typeorm";

export type AuthMethod = "password" | "oauth" | "mfa" | "jwt";

@Entity("users")
export class User {
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  /** Normalized (NFKC, lower-case). Null for accounts created through OAuth. */
  @Column("text", { unique: true, nullable: true })
  username!: string | null;

  @Column("text")
  displayName!: string;

  @Column("text", { nullable: true })
  email!: string | null;

  /** argon2id PHC string: algorithm, cost parameters, random per-password salt and digest. Null for OAuth-only users. */
  @Column("text", { nullable: true })
  passwordHash!: string | null;

  @Column("boolean", { default: false })
  mfaEnabled!: boolean;

  /** TOTP shared secret, AES-256-GCM encrypted (never stored in plaintext). */
  @Column("text", { nullable: true })
  totpSecretEnc!: string | null;

  /** Last accepted TOTP time-step; codes at or before it are rejected (replay protection). */
  @Column("integer", { nullable: true })
  totpLastUsedStep!: number | null;

  @Column("integer", { default: 0 })
  failedLoginAttempts!: number;

  @Column("datetime", { nullable: true })
  lockedUntil!: Date | null;

  /** Embedded in JWTs; bumping it revokes every outstanding access token. */
  @Column("integer", { default: 0 })
  tokenVersion!: number;

  @Column("datetime", { nullable: true })
  lastLoginAt!: Date | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}

@Entity("oauth_accounts")
@Unique(["provider", "subject"])
export class OAuthAccount {
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @Column("text")
  provider!: string;

  /** Provider's stable user id (`sub`). Accounts are linked by (provider, sub), never by email. */
  @Column("text")
  subject!: string;

  @ManyToOne(() => User, { onDelete: "CASCADE", nullable: false })
  user!: User;

  @CreateDateColumn()
  createdAt!: Date;
}

/** Server-side session. The primary key is SHA-256(session token); the raw token only lives in the cookie. */
@Entity("sessions")
export class Session {
  @PrimaryColumn("text")
  id!: string;

  @ManyToOne(() => User, { onDelete: "CASCADE", nullable: false })
  user!: User;

  @Column("text")
  authMethod!: AuthMethod;

  @Column("datetime")
  lastSeenAt!: Date;

  /** Absolute expiry; idle expiry is derived from lastSeenAt. */
  @Column("datetime")
  expiresAt!: Date;

  @Column("text", { nullable: true })
  ip!: string | null;

  @Column("text", { nullable: true })
  userAgent!: string | null;

  @CreateDateColumn()
  createdAt!: Date;
}

/** Opaque rotating refresh token. Primary key is SHA-256(token). */
@Entity("refresh_tokens")
export class RefreshToken {
  @PrimaryColumn("text")
  id!: string;

  @ManyToOne(() => User, { onDelete: "CASCADE", nullable: false })
  user!: User;

  /** All tokens descending from one login share a family; reuse of a rotated token revokes the family. */
  @Index()
  @Column("text")
  familyId!: string;

  @Column("datetime")
  expiresAt!: Date;

  @Column("datetime", { nullable: true })
  usedAt!: Date | null;

  @Column("datetime", { nullable: true })
  revokedAt!: Date | null;

  @CreateDateColumn()
  createdAt!: Date;
}

@Entity("recovery_codes")
export class RecoveryCode {
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @ManyToOne(() => User, { onDelete: "CASCADE", nullable: false })
  user!: User;

  /** SHA-256 of the code. Codes carry ~50 bits of entropy, so a fast hash suffices. */
  @Column("text")
  codeHash!: string;

  @Column("datetime", { nullable: true })
  usedAt!: Date | null;
}

/** Pending second factor after a correct password. Primary key is SHA-256(challenge token). */
@Entity("mfa_challenges")
export class MfaChallenge {
  @PrimaryColumn("text")
  id!: string;

  @ManyToOne(() => User, { onDelete: "CASCADE", nullable: false })
  user!: User;

  @Column("text")
  kind!: "verify" | "enroll";

  /** Encrypted candidate TOTP secret during enrollment; promoted to the user only after a valid code. */
  @Column("text", { nullable: true })
  pendingSecretEnc!: string | null;

  @Column("integer", { default: 0 })
  attempts!: number;

  @Column("datetime")
  expiresAt!: Date;
}

/** OAuth `state` → PKCE code_verifier, single use. Primary key is SHA-256(state). */
@Entity("oauth_states")
export class OAuthState {
  @PrimaryColumn("text")
  id!: string;

  @Column("text")
  provider!: string;

  @Column("text")
  codeVerifier!: string;

  @Column("datetime")
  expiresAt!: Date;
}

/** Security audit trail. */
@Entity("auth_events")
export class AuthEvent {
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @Index()
  @Column("text", { nullable: true })
  userId!: string | null;

  @Column("text")
  type!: string;

  @Column("boolean")
  success!: boolean;

  @Column("text", { nullable: true })
  detail!: string | null;

  @Column("text", { nullable: true })
  ip!: string | null;

  @Column("text", { nullable: true })
  userAgent!: string | null;

  /** Set explicitly (millisecond precision) so events within the same second keep their order. */
  @Index()
  @Column("datetime")
  createdAt!: Date;
}

export const entities = [User, OAuthAccount, Session, RefreshToken, RecoveryCode, MfaChallenge, OAuthState, AuthEvent];
