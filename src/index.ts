import { parse, stringify } from 'yaml';
import fs from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import shell from 'shelljs';
import { Prompt } from '@poppinss/prompts';
import { logger } from '@poppinss/cliui';

type TlsConfig = {
  tls: {
    certificates: Array<{
      certFile: string;
      keyFile: string;
    }>;
  };
};

type RootCertificateDefinition = {
  certificate: string;
  key: string;
};

const traefikDir = join(homedir(), '.apps', 'local_env', 'with_custom_domains');
const certsConfigPath = join(traefikDir, 'tls.yml');
const certsDir = join(homedir(), '.certs');
const ROOT_CA = {
  certificate: 'root.pem',
  key: 'root.key',
};
const prompt = new Prompt();
const os = platform();

async function start(): Promise<void> {
  if (!['darwin', 'linux', 'win32'].includes(os)) {
    logger.error('Your operating system is not supported by this tool.');
    process.exit(1);
  }

  if (os === 'win32') {
    logger.info('If you are running on Windows, you need to execute this tool inside WSL in order to work with openssl.');
  }

  const action = await prompt.choice('What action to execute ?', [
    { name: 'root_ca', hint: 'Add a new certificate for a site' },
    { name: 'site_cert', hint: 'Create CA authority on my machine' },
  ]);

  if (action === 'root_ca') {
    createCertificateAuthority();
    return;
  }

  if (action === 'site_cert') {
    const domain = await prompt.ask('Domain to use for this site', {
      hint: 'It must end with `.test`',
      validate(answer) {
        if (!answer) {
          return 'You need to choose a domain.';
        }

        if (!answer.endsWith('.test')) {
          return 'Your domain has to end with the `.test` extension.'
        }

        return true;
      },
    });

    addNewCertificate(domain);
    return;
  }
}

function getCertificateSubject(domain?: string) {
  return `/C=FR/ST=azerty/L=azerty/O=azerty/OU=azerty/CN=${domain ?? 'Root CA'}`;
}

function createCertificateAuthority(): void {
  const platformVariants: Partial<Record<NodeJS.Platform, { keyCmd: string; certCmd: string; doc: string; }>> = {
    win32: {
      keyCmd: 'winpty openssl genrsa -des3 -out root.key 2048',
      certCmd: `winpty openssl req -x509 -new -nodes -key root.key -sha256 -days 1825 -out root.pem -subj "${getCertificateSubject()}"`,
      doc: 'https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/#adding-root-cert-macos-keychain',
    },
    darwin: {
      keyCmd: 'openssl genrsa -des3 -out root.key 2048',
      certCmd: `openssl req -x509 -new -nodes -key root.key -sha256 -days 1825 -out root.pem -subj "${getCertificateSubject()}"`,
      doc: 'https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/#adding-root-cert-macos-keychain',
    },
    linux: {
      keyCmd: 'openssl genrsa -des3 -out root.key 2048',
      certCmd: `openssl req -x509 -new -nodes -key root.key -sha256 -days 1825 -out root.pem -subj "${getCertificateSubject()}"`,
      doc: 'https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/#adding-root-cert-linux-keychain',
    },
  };

  const alreadyExists = shell.ls(certsDir).filter((file) => {
    return file === ROOT_CA.certificate || file === ROOT_CA.key;
  });

  if (alreadyExists.length === 2) {
    logger.info('Root certificate authority already exist.');
    process.exit(0);
  }

  logger.info('Creating key...');
  shell.exec(platformVariants[os]!.keyCmd, { cwd: certsDir });
  logger.info('Creating certificate...');
  shell.exec(platformVariants[os]!.certCmd, { cwd: certsDir });
  logger.success('Certificate authority created with name `root.pem` and key `root.key`');
  logger.info(`You need to trust the certificate authority on your machine. View ${platformVariants[os]!.doc} for more info.`);
}

function verifyRootCertificates() {
  const alreadyExists = shell.ls(certsDir).filter((file) => {
    return file === ROOT_CA.certificate || file === ROOT_CA.key;
  });

  if (alreadyExists.length !== 2) {
    logger.error('Root certificate authority do not exist. You can generate it with selecting the second option of this CLI.');
    process.exit(1);
  }

  const certsDefinition = {
    certificate: '',
    key: '',
  } satisfies RootCertificateDefinition;

  for (const file of alreadyExists) {
    if (file === ROOT_CA.certificate) {
      certsDefinition.certificate = file;
    } else {
      certsDefinition.key = file;
    }
  }

  return certsDefinition;
}

function createExtensionString(domain: string): string {
  return `authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names\n
[alt_names]
DNS.1 = ${domain}
DNS.2 = *.${domain}
`;
}

function addNewCertificate(domainName: string): void {
  verifyRootCertificates();

  const file = fs.readFileSync(certsConfigPath, { encoding: 'utf8' });
  const parsedFile = parse(file) as TlsConfig;
  const existingCerts = parsedFile.tls.certificates;

  const entryExists = existingCerts.find((cert) => {
    const certFile = cert.certFile;
    const regexp = new RegExp(/^\/etc\/ssl\/traefik\/(?<domain>[a-zA-Z-_.]+)\.crt$/);
    const domain = certFile.match(regexp);

    if (domain && domain.groups?.domain) {
      return domain.groups.domain === domainName;
    }

    return false;
  });

  if (entryExists !== undefined) {
    logger.error('This domain is already registered locally. Please choose another one.');
    process.exit(1);
  }

  if (entryExists === undefined) {
    generateCertificate(domainName);

    parsedFile.tls.certificates.push({
      certFile: `/etc/ssl/traefik/${domainName}.crt`,
      keyFile: `/etc/ssl/traefik/${domainName}.key`,
    });

    fs.writeFileSync(certsConfigPath, stringify(parsedFile));
  }
}

function generateCertificate(domainName: string): void {
  shell.exec(`openssl genrsa -out ${domainName}.key 2048`, { cwd: certsDir });
  shell.exec(`openssl req -new -key ${domainName}.key -out ${domainName}.csr -subj "${getCertificateSubject(domainName)}"`, { cwd: certsDir });
  fs.writeFileSync(join(certsDir, `${domainName}.ext`), createExtensionString(domainName));
  shell.exec(`openssl x509 -req -in ${domainName}.csr -CA root.pem -CAkey root.key -CAcreateserial -out ${domainName}.crt -days 825 -sha256 -extfile ${domainName}.ext`, { cwd: certsDir });
}

await start();
