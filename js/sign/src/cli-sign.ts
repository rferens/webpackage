import { KeyObject } from 'crypto';
import * as fs from 'fs';
import { createRequire } from 'module';

import { Command } from 'commander';

import {
  errorLog,
  greenConsoleLog,
  infoLog,
  parseMaybeEncryptedKeyFromFile,
  warnLog,
} from './utils/cli-utils.js';
import {
  IntegrityBlockSigner,
  NodeCryptoSigningStrategy,
  WebBundleId,
} from './wbn-sign.js';

const require = createRequire(import.meta.url);
const { name, version } = require('../package.json');

const program = new Command()
  .name(name)
  .version(version)
  .description(
    `A simple CLI tool for managing signatures and keys of (signed) web bundles.
The primary use case is signing web bundles with private keys.`
  );

async function parseArguments(): Promise<void> {
  // The main use case - signing web bundles
  program
    .command('sign')
    .description(
      'Signs the given web bundle with private key(s). Produces signed web bundle output file.'
    )
    .argument('<web_bundle>', 'a web bundle (file `*.wbn`) to sign')
    .argument(
      '<private_keys...>',
      'private keys (files `*.pem`) with which the web bundle will be signed. EcdsaP256 and ed25519 keys (encrypted and not encrypted) are supported.'
    )
    .option(
      '-o, --output <file>',
      'signed web bundle output file',
      /*defaultValue=*/ 'signed.swbn'
    )
    .option(
      '--web-bundle-id <web-bundle-id>',
      'web bundle ID. Derived from the first key if not specified.'
    )
    .showHelpAfterError()
    .action(async (webBundle, privateKeys, options) => {
      if (!options.webBundleId) {
        infoLog(
          `The bundle id was not specified. It will be derived from the ${
            privateKeys.length > 1 ? 'first ' : ''
          }given key.`
        );
      }
      await readFilesAndSignWebBundle(
        webBundle,
        privateKeys,
        options.output,
        options.webBundleId
      );
    });

  program
    .command('sing', { hidden: true })
    .argument('[anything...]')
    .action(() => {
      greenConsoleLog('🎶 Never gonna let you down, lalala la lala... 🎶 \n');
      errorLog("Unrecognized command 'sing'. Use 'sign' instead.\n");
      process.exit(1);
    });

  // This default command provides backward compatibility.
  // The tool in the past only supported signing and didn't use commands.
  program
    .command('backward-compatibility-sign', { isDefault: true, hidden: true })
    // That's the workaround for proper error message, when an improper command is used.
    // It's then interpreted as an argument of the default command, so falls here.
    .argument('[...]', '')
    .option('-i, --input <file>', 'input web bundle to be signed (required)')
    .option(
      '-k, --private-key <file...>',
      'paths to Ed25519 / ECDSA P-256 private key(s) (required)'
    )
    .option(
      '-o, --output <file>',
      'signed web bundle output file',
      /*defaultValue=*/ 'signed.swbn'
    )
    .option('--web-bundle-id <web-bundle-id>', 'web bundle ID')
    // Command-specific error message on parsing error (e.g. no value, or incorrect option)
    .showHelpAfterError()
    .action(async (args, options, command) => {
      // Wrong command
      if (args.length > 0) {
        // Help finishes the program internally
        program.help();
      }

      // Does it seem like old usage? If not just show help.
      if (
        !('input' in options) &&
        !('privateKey' in options) &&
        !('webBundleId' in options)
      ) {
        program.help();
      }

      // Backward-compatible mode
      warnLog(
        'This `wbn-sign` usage is deprecated. Please check `wbn-sign help`. This CLI usage form may be not supported in the future.'
      );

      if (!('input' in options) || !('privateKey' in options)) {
        errorLog(
          `input and private key options are required! Please, consider using new cli (see \`wbn-sign help\`)`
        );
        command.help();
      }

      if (options.privateKey.length > 1 && !options.webBundleId) {
        errorLog(
          `--web-bundle-id must be specified if there's more than 1 signing key involved.`
        );
        command.help();
      }

      await readFilesAndSignWebBundle(
        options.input,
        options.privateKey,
        options.output,
        options.webBundleId
      );
    });

  program.helpCommand(true);

  await program.parseAsync(process.argv);
}

async function readFilesAndSignWebBundle(
  wbnFilePath: string,
  keyFilesPaths: string[],
  outputFilePath: string,
  maybeWebBundleId?: string
) {
  const webBundle = fs.readFileSync(wbnFilePath);

  const privateKeys = new Array<KeyObject>();
  for (const privateKey of keyFilesPaths) {
    privateKeys.push(await parseMaybeEncryptedKeyFromFile(privateKey));
  }

  const webBundleId =
    maybeWebBundleId ?? new WebBundleId(privateKeys[0]).serialize();

  const signer = new IntegrityBlockSigner(
    Uint8Array.from(webBundle),
    webBundleId,
    privateKeys.map((privateKey) => new NodeCryptoSigningStrategy(privateKey))
  );
  const { signedWebBundle } = await signer.sign();
  greenConsoleLog(`${webBundleId}`);
  fs.writeFileSync(outputFilePath, signedWebBundle);
}

export async function main() {
  await parseArguments();
}
