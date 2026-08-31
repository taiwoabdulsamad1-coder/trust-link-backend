import { Global, Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import { ConfigService } from './config.service';
import { configValidationSchema } from './config.schema';

/**
 * Custom Joi validator for Stellar secret keys.
 *
 * Validates by DECODING the key via Keypair.fromSecret, not pattern matching
 * alone. This catches checksum errors that the pattern /^S[A-Z2-7]{55}$/ cannot
 * detect.
 *
 * Rejects:
 * - Shape-valid but checksum-invalid keys (e.g. SAAAAAAA...AAAA)
 * - Public keys supplied where a secret key is expected (G... keys)
 * - Completely malformed strings
 */
const stellarSecretKey = Joi.string().custom((value: string, helpers) => {
  const keyName = helpers.state.path ? helpers.state.path.join('.') : 'key';
  // Quick shape check first for better error messages
  if (!value.startsWith('S')) {
    return helpers.message({
      custom:
        `${keyName} must be a Stellar secret key ` +
        `starting with S, got a value starting with '${value[0]}'`,
    });
  }

  try {
    Keypair.fromSecret(value);
    return value; // valid — checksum passed
  } catch {
    return helpers.message({
      custom:
        `${keyName} is an invalid Stellar secret key ` +
        `— checksum verification failed. ` +
        `Check the key value in your environment configuration.`,
    });
  }
}, 'Stellar secret key checksum validation');

/**
 * Custom Joi validator for Stellar public keys (G... addresses).
 *
 * Validates by decoding via Keypair.fromPublicKey. Rejects secret keys,
 * malformed strings, and checksum failures.
 */
const stellarPublicKey = Joi.string().custom((value: string, helpers) => {
  const keyName = helpers.state.path ? helpers.state.path.join('.') : 'key';
  if (!value.startsWith('G')) {
    return helpers.message({
      custom:
        `${keyName} must be a Stellar public key ` +
        `starting with G, got a value starting with '${value[0]}'`,
    });
  }

  try {
    Keypair.fromPublicKey(value);
    return value; // valid
  } catch {
    return helpers.message({
      custom:
        `${keyName} is an invalid Stellar public key ` +
        `— checksum verification failed.`,
    });
  }
}, 'Stellar public key checksum validation');

@Global()
@Module({
  imports: [
    NestConfigModule.forRoot({
      validationSchema: configValidationSchema,
      ignoreEnvFile: true,
      validationOptions: {
        abortEarly: false,
        allowUnknown: true,
      },
    }),
  ],
  providers: [ConfigService],
  exports: [ConfigService],
})
export class ConfigModule {}