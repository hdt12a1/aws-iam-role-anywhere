# Creating a Trust Anchor Certificate Bundle for IAM Role Anywhere

A trust anchor certificate bundle is a collection of certificates that establish the chain of trust for IAM Role Anywhere. This guide provides step-by-step instructions for creating a trust anchor using different approaches.

## Table of Contents

- [Option 1: Using AWS Private CA](#option-1-using-aws-private-ca)
- [Option 2: Using OpenSSL (Self-managed CA)](#option-2-using-openssl-self-managed-ca)
- [Option 3: Using an Existing Enterprise PKI](#option-3-using-an-existing-enterprise-pki)
- [Verifying Your Certificate Bundle](#verifying-your-certificate-bundle)
- [Registering the Trust Anchor with IAM Role Anywhere](#registering-the-trust-anchor-with-iam-role-anywhere)

## Option 1: Using AWS Private CA

1. **Create a Root CA in AWS Private CA**:

   ```bash
   aws acm-pca create-certificate-authority \
     --certificate-authority-configuration file://ca-config.json \
     --certificate-authority-type ROOT \
     --idempotency-token 1234567890 \
     --tags Key=Name,Value=RoleAnywhereRootCA
   ```

   Example `ca-config.json`:
   ```json
   {
     "KeyAlgorithm": "RSA_4096",
     "SigningAlgorithm": "SHA512WITHRSA",
     "Subject": {
       "Country": "US",
       "Organization": "Example Corp",
       "OrganizationalUnit": "Security",
       "State": "Washington",
       "Locality": "Seattle",
       "CommonName": "Example Corp Root CA"
     }
   }
   ```

2. **Get the Certificate Authority ARN**:

   ```bash
   export CA_ARN=$(aws acm-pca list-certificate-authorities \
     --query 'CertificateAuthorities[?Status==`ACTIVE`].Arn' \
     --output text)
   ```

3. **Generate a Certificate Signing Request (CSR)**:

   ```bash
   aws acm-pca get-certificate-authority-csr \
     --certificate-authority-arn $CA_ARN \
     --output text > rootca.csr
   ```

4. **Issue the Root CA Certificate**:

   ```bash
   aws acm-pca issue-certificate \
     --certificate-authority-arn $CA_ARN \
     --csr fileb://rootca.csr \
     --signing-algorithm SHA512WITHRSA \
     --template-arn arn:aws:acm-pca:::template/RootCACertificate/V1 \
     --validity Value=10,Type=YEARS
   ```

5. **Import the Certificate**:

   ```bash
   aws acm-pca import-certificate-authority-certificate \
     --certificate-authority-arn $CA_ARN \
     --certificate fileb://rootca.pem
   ```

6. **Download the Root CA Certificate**:

   ```bash
   aws acm-pca get-certificate-authority-certificate \
     --certificate-authority-arn $CA_ARN \
     --output text --query 'Certificate' > rootca.pem
   ```

## Option 2: Using OpenSSL (Self-managed CA)

1. **Create a Root CA Key**:

   ```bash
   # Generate a private key for the Root CA
   openssl genrsa -out rootca-key.pem 4096
   ```

2. **Create a Root CA Certificate**:

   ```bash
   # Create a configuration file for the Root CA
   cat > rootca.cnf << EOF
   [req]
   distinguished_name = req_distinguished_name
   prompt = no
   x509_extensions = v3_ca
   
   [req_distinguished_name]
   C = US
   ST = Washington
   L = Seattle
   O = Example Corp
   OU = Security
   CN = Example Corp Root CA
   
   [v3_ca]
   subjectKeyIdentifier = hash
   authorityKeyIdentifier = keyid:always,issuer:always
   basicConstraints = critical, CA:true
   keyUsage = critical, digitalSignature, cRLSign, keyCertSign
   EOF
   
   # Generate the Root CA certificate
   openssl req -new -x509 -days 3650 -key rootca-key.pem -out rootca.pem -config rootca.cnf
   ```

3. **Create the Certificate Bundle**:

   ```bash
   # For a bundle with just the Root CA
   cp rootca.pem trust-anchor-bundle.pem
   ```

   > **Note**: For production environments, it's generally recommended to use a hierarchical PKI with intermediate CAs. However, for simplicity in this guide, we're focusing on a single Root CA approach.

## Option 3: Using an Existing Enterprise PKI

If you already have an enterprise PKI:

1. **Export the Root CA Certificate**:
   - From your CA management console, export the Root CA certificate in PEM format

2. **Export any Intermediate CA Certificates** (if applicable):
   - Export all intermediate certificates in the chain in PEM format

3. **Create the Certificate Bundle**:

   ```bash
   # For a single Root CA
   cp rootca.pem trust-anchor-bundle.pem
   
   # For a chain with intermediates (order matters: leaf to root)
   cat intermediate1.pem intermediate2.pem rootca.pem > trust-anchor-bundle.pem
   ```

## Verifying Your Certificate Bundle

Verify that your certificate bundle is properly formatted:

```bash
# View certificate information
openssl x509 -in trust-anchor-bundle.pem -text -noout

# If you have multiple certificates in the bundle, use this to view all
openssl crl2pkcs7 -nocrl -certfile trust-anchor-bundle.pem | openssl pkcs7 -print_certs -text -noout
```

Ensure that:
1. The certificate has the CA:TRUE flag in the Basic Constraints
2. The Key Usage includes keyCertSign and cRLSign
3. The certificate is not expired

## Registering the Trust Anchor with IAM Role Anywhere

Once you have your trust anchor certificate bundle:

```bash
# Register the trust anchor
aws rolesanywhere create-trust-anchor \
  --name "MyTrustAnchor" \
  --source "sourceData={x509CertificateData=$(cat trust-anchor-bundle.pem | base64 -w 0)}" \
  --enabled
```

Store the returned trust anchor ARN for use with the AWS signing helper:

```bash
export TRUST_ANCHOR_ARN=$(aws rolesanywhere list-trust-anchors \
  --query 'trustAnchors[?name==`MyTrustAnchor`].trustAnchorArn' \
  --output text)
```

## Security Best Practices

1. **Protect Private Keys**: Store CA private keys securely, ideally in a hardware security module (HSM)
2. **Use Strong Cryptography**: Use RSA 4096 or ECC P-384 keys with SHA-256 or stronger hashing algorithms
3. **Implement Key Rotation**: Plan for CA certificate rotation before expiration
4. **Limit Access**: Restrict access to CA management functions to authorized personnel only
5. **Document Procedures**: Create clear documentation for certificate issuance, renewal, and revocation
