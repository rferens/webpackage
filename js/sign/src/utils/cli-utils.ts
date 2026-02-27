import { KeyObject } from 'crypto';
import fs from 'fs';
import path from 'path';

import read from 'read';

import { parsePemKey } from '../wbn-sign.js';

// Parses either an unencrypted or encrypted private key. For encrypted keys, it
// reads the passphrase to decrypt them from either the
// `WEB_BUNDLE_SIGNING_PASSPHRASE` environment variable, or, if not set, prompts
// the user for the passphrase.
export async function parseMaybeEncryptedKeyFromFile(
  filePath: string
): Promise<KeyObject> {
  return parseMaybeEncryptedKey(
    fs.readFileSync(filePath),
    path.basename(filePath)
  );
}

// Exported for testing.
export async function parseMaybeEncryptedKey(
  data: Buffer,
  description: string = ''
): Promise<KeyObject> {
  // Read unencrypted private key.
  try {
    return parsePemKey(data);
  } catch {
    infoLog('The provided key is probably encrypted. Decrypting attempt...');
  }

  const hasEnvVarSet =
    process.env.WEB_BUNDLE_SIGNING_PASSPHRASE &&
    process.env.WEB_BUNDLE_SIGNING_PASSPHRASE !== '';

  // Read encrypted private key.
  try {
    return parsePemKey(
      data,
      hasEnvVarSet
        ? process.env.WEB_BUNDLE_SIGNING_PASSPHRASE
        : await readPassphrase(description)
    );
  } catch (err) {
    throw Error(
      `Failed decrypting encrypted private key with passphrase read from ${
        hasEnvVarSet
          ? '`WEB_BUNDLE_SIGNING_PASSPHRASE` environment variable'
          : 'prompt'
      }`,
      { cause: err }
    );
  }
}

// A helper function that can be used to get the passphrase to decrypt a
// password-decrypted private key from user.
export async function readPassphrase(description: string): Promise<string> {
  try {
    const passphrase = await read({
      prompt: `Passphrase for the key ${description}: `,
      silent: true,
      replace: '*',
      // Output must be != `stdout`. Otherwise saving the `wbn-dump-id`
      // result into a file or an environment variable also includes the prompt.
      output: process.stderr,
    });
    return passphrase;
  } catch (err) {
    throw new Error('Reading passphrase failed.', { cause: err });
  }
}

// Logging module
//TODO: Replace with more professional js logging tools

const COLORS: Record<string, string> = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  //aka reset
  default: '\x1b[0m',
};

function coloredConsoleLog(
  colorEscCode: string,
  text: string,
  stream: NodeJS.WriteStream = process.stdout
): void {
  const reset = COLORS.default;

  // Check if the stream is a TTY (interactive terminal)
  // If the log is used for non-terminal (fd != 1), e.g., setting an environment
  // variable, it shouldn't have any formatting.
  if (stream.isTTY) {
    stream.write(`${colorEscCode}${text}${reset}\n`);
  } else {
    stream.write(`${text}\n`);
  }
}

export function greenConsoleLog(text: string): void {
  coloredConsoleLog(COLORS.green, text);
}
export function infoLog(text: string): void {
  coloredConsoleLog(COLORS.default, 'INFO: ' + text, process.stderr);
}
export function warnLog(text: string): void {
  coloredConsoleLog(COLORS.yellow, 'WARN: ' + text, process.stderr);
}
export function errorLog(text: string): void {
  coloredConsoleLog(COLORS.red, 'ERROR: ' + text, process.stderr);
}
