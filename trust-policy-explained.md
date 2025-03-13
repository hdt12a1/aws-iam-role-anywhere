# IAM Role Anywhere Trust Policy Explained

This document explains the IAM trust policy used for IAM Role Anywhere:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "rolesanywhere.amazonaws.com"
            },
            "Action": [
                "sts:TagSession",
                "sts:SetSourceIdentity",
                "sts:AssumeRole"
            ],
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalTag/x509Subject/CN": "ibond-bond-event-handler"
                },
                "ArnEquals": {
                    "aws:SourceArn": "arn:aws:rolesanywhere:ap-southeast-1:793169198739:trust-anchor/f96c523d-7c98-4b9a-af27-18475cf83d68"
                }
            }
        }
    ]
}
```

## Policy Breakdown

### Basic Structure

- **Version**: `"2012-10-17"` - The policy language version (always this value for current policies)
- **Statement**: An array containing permission statements

### Permission Statement

#### Trust Relationship

- **Effect**: `"Allow"` - This statement grants permissions rather than denying them
- **Principal**: `{"Service": "rolesanywhere.amazonaws.com"}` - Specifies that only the IAM Role Anywhere service can assume this role

#### Allowed Actions

```json
"Action": [
    "sts:TagSession",
    "sts:SetSourceIdentity",
    "sts:AssumeRole"
]
```

- **sts:AssumeRole**: Allows IAM Role Anywhere to assume this role and obtain temporary credentials
- **sts:TagSession**: Allows IAM Role Anywhere to add tags to the session when the role is assumed
- **sts:SetSourceIdentity**: Allows IAM Role Anywhere to set a source identity for the session

#### Condition Constraints

```json
"Condition": {
    "StringEquals": {
        "aws:PrincipalTag/x509Subject/CN": "ibond-bond-event-handler"
    },
    "ArnEquals": {
        "aws:SourceArn": "arn:aws:rolesanywhere:ap-southeast-1:793169198739:trust-anchor/f96c523d-7c98-4b9a-af27-18475cf83d68"
    }
}
```

This section adds two critical security constraints:

1. **Certificate Common Name Restriction**:
   - `"aws:PrincipalTag/x509Subject/CN": "ibond-bond-event-handler"` 
   - Only allows certificates with the Common Name (CN) "ibond-bond-event-handler" to use this role
   - The X.509 certificate subject fields are passed as principal tags by IAM Role Anywhere

2. **Trust Anchor Restriction**:
   - `"aws:SourceArn": "arn:aws:rolesanywhere:ap-southeast-1:793169198739:trust-anchor/f96c523d-7c98-4b9a-af27-18475cf83d68"`
   - Only allows requests from the specified trust anchor
   - Prevents other trust anchors in your account from using this role

## Security Implications

This policy implements the principle of least privilege by:

1. **Service Restriction**: Only the IAM Role Anywhere service can assume the role
2. **Certificate Identity Binding**: Only certificates with a specific CN can use the role
3. **Trust Anchor Binding**: Only a specific trust anchor can be used with this role

## How It Works in Practice

1. A workload presents an X.509 certificate to IAM Role Anywhere
2. IAM Role Anywhere validates the certificate against the specified trust anchor
3. If valid, IAM Role Anywhere checks if the certificate's CN matches "ibond-bond-event-handler"
4. If it matches, IAM Role Anywhere assumes the role and returns temporary credentials to the workload

## Customization Options

You can modify this policy to:

1. **Support multiple CNs**:
   ```json
   "aws:PrincipalTag/x509Subject/CN": ["service1", "service2", "service3"]
   ```

2. **Use other certificate fields**:
   ```json
   "aws:PrincipalTag/x509Subject/OU": "IT"
   ```

3. **Add IP address restrictions**:
   ```json
   "IpAddress": {
     "aws:SourceIp": ["192.0.2.0/24", "203.0.113.0/24"]
   }
   ```

4. **Allow multiple trust anchors**:
   ```json
   "ArnLike": {
     "aws:SourceArn": "arn:aws:rolesanywhere:ap-southeast-1:793169198739:trust-anchor/*"
   }
   ```
