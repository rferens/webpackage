import { exec } from 'child_process';
import fs from 'fs';
import { createRequire } from 'module';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { promisify } from 'util';

const execPromise = promisify(exec);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { version } = require('../package.json');

const PASSPHRASE = 'helloworld';

describe('CLI wbn-sign:', () => {
  const cliPath = path.resolve(__dirname, '../bin/wbn-sign.js');
  const unsignedWbnPath = path.resolve(__dirname, 'testdata/unsigned.wbn');
  const ed25519KeyPath = path.resolve(__dirname, 'testdata/ed25519-key-1.pem');
  const ed25519EncryptedKeyPath = path.resolve(
    __dirname,
    'testdata/ed25519-encrypted-key-1.pem'
  );
  const ecdsaP256KeyPath = path.resolve(
    __dirname,
    'testdata/ecdsaP256-key-1.pem'
  );
  const ecdsaP256EncryptedKeyPath = path.resolve(
    __dirname,
    'testdata/ecdsaP256-encrypted-key-1.pem'
  );

  let tmpDir;
  let outputPath;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wbn-sign-test-'));
    // Will be cleaned after each test case
    outputPath = path.join(tmpDir, 'signed.swbn');
  });

  afterEach(() => {
    fs.rmSync(outputPath, { force: true });
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('Version command', async () => {
    const { stdout: stdoutLong } = await execPromise(
      `node ${cliPath} --version`
    );
    expect(stdoutLong).toContain(version);

    const { stdout: stdoutShort } = await execPromise(`node ${cliPath} -V`);
    expect(stdoutShort).toContain(version);
  });

  it('Help command', async () => {
    const helpUsageFragment = 'Usage: wbn-sign [options] [command]';

    let { stdout } = await execPromise(`node ${cliPath} --help`);
    expect(stdout).toContain(helpUsageFragment);
    expect(stdout).toContain('sign [options] <web_bundle> <private_keys...>');

    // Short form
    ({ stdout } = await execPromise(`node ${cliPath} -h`));
    expect(stdout).toContain(helpUsageFragment);

    // Command form
    ({ stdout } = await execPromise(`node ${cliPath} help`));
    expect(stdout).toContain(helpUsageFragment);

    // No arguments
    ({ stdout } = await execPromise(`node ${cliPath}`));
    expect(stdout).toContain(helpUsageFragment);

    // Wrong command
    ({ stdout } = await execPromise(`node ${cliPath} wrong_command`));
    expect(stdout).toContain(helpUsageFragment);
  });

  it('Sign command - ed25519 success', async () => {
    const { stdout, stderr } = await execPromise(
      `node ${cliPath} sign -o ${outputPath} ${unsignedWbnPath} ${ed25519KeyPath}`
    );
    expect(stderr.includes('ERROR')).toBeFalse();
    expect(stderr.includes('WARNING')).toBeFalse();
    expect(stdout).toContain(
      '4tkrnsmftl4ggvvdkfth3piainqragus2qbhf7rlz2a3wo3rh4wqaaic'
    );
    expect(fs.existsSync(outputPath)).toBeTrue();
  });

  it('Sign command - ecdsaP256 success', async () => {
    const { stdout, stderr } = await execPromise(
      `node ${cliPath} sign -o ${outputPath} ${unsignedWbnPath} ${ecdsaP256KeyPath}`
    );
    expect(stderr.includes('ERROR')).toBeFalse();
    expect(stderr.includes('WARNING')).toBeFalse();
    expect(stdout).toContain(
      'apacrs6uf4bze5pnpwc7xqca4uteyvo7iyfnbzxs7wys4ochzgbpiaacai'
    );
    expect(fs.existsSync(outputPath)).toBeTrue();
  });

  it('Sign command - encrypted ed25519 success', (done) => {
    const child_process = exec(
      `node ${cliPath} sign -o ${outputPath} ${unsignedWbnPath} ${ed25519EncryptedKeyPath}`,
      {},
      (error, stdout, stderr) => {
        expect(stderr).toContain('Passphrase for the key');
        expect(stdout).toContain(
          '4tkrnsmftl4ggvvdkfth3piainqragus2qbhf7rlz2a3wo3rh4wqaaic'
        );
        expect(fs.existsSync(outputPath)).toBeTrue();
        done();
      }
    );
    child_process.stdin.write(`${PASSPHRASE}\n`);
    child_process.stdin.end();
  });

  it('Sign command - encrypted ecdsaP256 success', (done) => {
    const child_process = exec(
      `node ${cliPath} sign -o ${outputPath} ${unsignedWbnPath} ${ecdsaP256EncryptedKeyPath}`,
      {},
      (error, stdout, stderr) => {
        expect(stderr).toContain('Passphrase for the key');
        expect(stdout).toContain(
          'apacrs6uf4bze5pnpwc7xqca4uteyvo7iyfnbzxs7wys4ochzgbpiaacai'
        );
        expect(fs.existsSync(outputPath)).toBeTrue();
        done();
      }
    );
    child_process.stdin.write(`${PASSPHRASE}\n`);
    child_process.stdin.end();
  });

  it('Sign command - bundle id override success', async () => {
    const { stdout, stderr } = await execPromise(
      `node ${cliPath} sign -o ${outputPath} --web-bundle-id 123456 ${unsignedWbnPath} ${ed25519KeyPath}`
    );
    expect(stderr).toBe('');
    expect(stdout).toContain('123456');
    expect(fs.existsSync(outputPath)).toBeTrue();
  });

  it('Sign command - multiple keys', (done) => {
    const child_process = exec(
      `node ${cliPath} sign -o ${outputPath} ${unsignedWbnPath} ${ed25519KeyPath} ${ecdsaP256EncryptedKeyPath}`,
      {},
      (error, stdout, stderr) => {
        expect(stderr).toContain('Passphrase for the key');
        expect(stdout).toContain(
          '4tkrnsmftl4ggvvdkfth3piainqragus2qbhf7rlz2a3wo3rh4wqaaic'
        );
        expect(fs.existsSync(outputPath)).toBeTrue();
        done();
      }
    );
    child_process.stdin.write(`${PASSPHRASE}\n`);
    child_process.stdin.end();
  });

  it('Sign command - encrypted, wrong password, fail', (done) => {
    const child_process = exec(
      `node ${cliPath} sign -o ${outputPath} ${unsignedWbnPath} ${ed25519EncryptedKeyPath}`,
      {},
      (error, stdout, stderr) => {
        expect(stderr).toContain('Failed decrypting');
        expect(fs.existsSync(outputPath)).toBeFalse();
        done();
      }
    );
    child_process.stdin.write(`password123\n`);
    child_process.stdin.end();
  });

  it('Sign command - missing arguments', async () => {
    try {
      await execPromise(`node ${cliPath} sign`);
      fail('Should have failed');
    } catch (error) {
      expect(error.stderr).toContain(
        "error: missing required argument 'web_bundle'"
      );
    }
  });

  it('Sing command (Easter egg)', async () => {
    try {
      await execPromise(`node ${cliPath} sing`);
      fail('Should have failed');
    } catch (error) {
      expect(error.stdout).toContain('Never gonna let you down');
      expect(error.stderr).toContain("Unrecognized command 'sing'");
      expect(error.code).toBe(1);
    }
  });

  it('Deprecated usage - success', async () => {
    const { stderr } = await execPromise(
      `node ${cliPath} -i ${unsignedWbnPath} -k ${ed25519KeyPath} -o ${outputPath}`
    );
    expect(stderr).toContain('This `wbn-sign` usage is deprecated');
    expect(fs.existsSync(outputPath)).toBeTrue();
  });

  it('Deprecated usage - missing -k', async () => {
    const { stderr } = await execPromise(
      `node ${cliPath} -i ${unsignedWbnPath}`
    );
    expect(stderr).toContain('This `wbn-sign` usage is deprecated');
    expect(stderr).toContain('input and private key options are required');
  });

  it('Deprecated usage - multi-key without web-bundle-id fails', async () => {
    const { stderr } = await execPromise(
      `node ${cliPath} -i ${unsignedWbnPath} -k ${ed25519KeyPath} ${ed25519KeyPath}`
    );
    expect(stderr).toContain(
      "--web-bundle-id must be specified if there's more than 1 signing key"
    );
  });
});
