# Node CLI tool to manage locally self-signed certificate

This tool aim to create on your machine a local Certificate Authority, based on openssl.
With it, you will be able to :

- Create your local CA without pain
- Generate certificate for each of your dev site (wildcard subdomain included)

## Install

```sh
# Locally clone this repo
git clone https://github.com/aureldvx/local_certificate_manager.git ~/local_certificate_manager

# Create certificates folder on your machine
mkdir -p ~/.certs

# Install dependencies (with your preferred package manager, pnpm for me)
pnpm install

# Build the tool
pnpm build

# Make the file executable
chmod +x ~/local_certificate_manager/dist/index.js

# Run it!
node ~/local_certificate_manager/dist/index.js
```

## Limitations

I have tested it on my MacBook M1, but it should be fine to use it on Windows and Linux too. The main requirement is the presence of openssl on your machine.

## Inspiration

- https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/ for their excellent article well detailed and explained
