# eSign API v3.3 - Spring Boot Implementation

A complete Spring Boot implementation of the eSign API Specification v3.3 as per Controller of Certifying Authorities (CCA), India.

## Features

### eSign Service (v3.3)
- **Document Signing API** - Submit documents for digital signing using e-KYC authentication
- **Status Check API** - Check the status of signing transactions
- **Callback Handling** - Asynchronous response delivery to ASP
- **Multiple Signature Types** - Raw, PKCS7, PKCS7pdf, PKCS7complete
- **Algorithms** - RSA and ECDSA support

### eKYC Service
- **User Management** - Create and manage eKYC user accounts
- **Multiple KYC Types**:
  - Offline Aadhaar XML
  - Bank eKYC
  - Organisational KYC
  - PAN KYC
  - Foreign National KYC
- **Multi-Factor Authentication**:
  - SMS OTP
  - TOTP (RFC 6238 compliant)
  - Mobile Access Token (MAT)
  - FIDO2 / WebAuthn
  - Public Key Authentication

### Security Features
- XML Digital Signature verification (Apache Santuario)
- HSM integration for key generation and signing
- PIN hashing with PBKDF2
- Rate limiting and account lockout
- Secure audit logging

## Technology Stack

- **Java 21**
- **Spring Boot 3.2.5**
- **Spring Data JPA** with PostgreSQL/H2
- **Spring Security**
- **Apache Santuario** (XML-DSig)
- **BouncyCastle** (Cryptography)
- **JAXB** (XML Binding)
- **Redis** (OTP storage)
- **Flyway** (Database migrations)
- **JUnit 5 + Mockito** (Testing)
- **Testcontainers** (Integration testing)

## Project Structure

```
src/main/java/in/gov/cca/esign/
├── config/                 # Configuration classes
├── controller/             # REST controllers
├── domain/                 # JPA entities
├── model/
│   ├── enums/              # Enumerations
│   └── xml/                # JAXB XML models
│       ├── esign/          # eSign request/response
│       └── ekyc/           # eKYC request/response
├── repository/             # Spring Data repositories
├── service/                # Service interfaces
├── service/impl/           # Service implementations
└── util/                   # Utility classes
```

## Getting Started

### Prerequisites

- Java 21+
- Maven 3.9+
- PostgreSQL 15+ (or H2 for development)
- Redis 7+ (for OTP storage)
- HSM/PKCS#11 provider (for production)

### Configuration

Copy `application.yml` and update the following properties:

```yaml
# Database
spring.datasource.url: jdbc:postgresql://localhost:5432/esign
spring.datasource.username: esign
spring.datasource.password: secret

# HSM Configuration
esign.hsm.provider: SunPKCS11
esign.hsm.slot: 0
esign.hsm.pin: 1234

# JWT Secret (min 32 chars)
security.jwt.secret: your-super-secret-key-at-least-32-characters

# FIDO2
ekyc.fido2.rp-id: esign.gov.in
ekyc.fido2.origin: https://esign.gov.in

# UIDAI Certificate URL
ekyc.uidai.certificate-url: https://www.uidai.gov.in/certificates/
```

### Build and Run

```bash
# Build
mvn clean package

# Run with development profile
mvn spring-boot:run -Dspring-boot.run.profiles=dev

# Run with production profile
java -jar target/esign-api-3.3.0.jar --spring.profiles.active=prod
```

### Database Migration

Flyway migrations run automatically on startup. The initial schema is in:
`src/main/resources/db/migration/V1__create_esign_tables.sql`

## API Endpoints

### eSign API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/esign/request` | Submit document for signing |
| POST | `/esign/status` | Check signing status |
| POST | `/esign/auth/callback` | Authentication callback |
| GET | `/esign/transaction/{id}` | Get transaction details |

### eKYC API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/ekyc/auth` | Authenticate user (composite/independent) |
| POST | `/ekyc/auth/second-factor` | Second factor authentication |
| POST | `/ekyc/bank-kyc` | Bank KYC registration |
| POST | `/ekyc/public-key/register` | Public key registration |

## Request/Response Format

All APIs use XML format as per eSign API v3.3 specification.

### eSign Request Example

```xml
<Esign ver="3.3" signerid="user@username.ESP001" 
       ts="2024-01-15T10:30:00+05:30" txn="TXN_123456" 
       maxWaitPeriod="60" aspId="ASP001" 
       responseUrl="https://asp.example.com/callback"
       signingAlgorithm="RSA">
  <Docs>
    <InputHash id="1" hashAlgorithm="SHA256" 
               docInfo="Loan Agreement" 
               docUrl="https://example.com/doc.pdf"
               responseSigType="PKCS7">
      a1b2c3d4e5f6...
    </InputHash>
  </Docs>
  <Signature>ASP_DIGITAL_SIGNATURE</Signature>
</Esign>
```

### eSign Response Example (Pending)

```xml
<EsignResp ver="3.3" status="2" ts="2024-01-15T10:30:01+05:30" 
           txn="TXN_123456" resCode="RESP_ABC123" />
```

### eSign Response Example (Success)

```xml
<EsignResp ver="3.3" status="1" ts="2024-01-15T10:35:00+05:30" 
           txn="TXN_123456" resCode="RESP_ABC123">
  <UserX509Certificate>BASE64_CERTIFICATE</UserX509Certificate>
  <Signatures>
    <DocSignature id="1" sigHashAlgorithm="SHA256">
      BASE64_SIGNATURE
    </DocSignature>
  </Signatures>
  <Signature>ESP_SIGNATURE</Signature>
</EsignResp>
```

## Testing

### Unit Tests

```bash
mvn test
```

### Integration Tests (with Testcontainers)

```bash
mvn verify -Pintegration-test
```

## Error Codes

| Code | Description |
|------|-------------|
| 101 | Invalid Request Format |
| 102 | Invalid Signer ID |
| 103 | Invalid Version |
| 104 | XML Signature validation failed |
| 105 | Invalid transaction ID |
| 106 | Invalid ASP ID |
| 107 | Invalid Digital Signature |
| 108 | Minimum one document is required |
| 109 | Request exceeds maximum documents |
| 110 | Invalid Timestamp |
| 113 | User Timeout |
| 114 | Authentication failed |
| 201-206 | Document level errors |
| 301-303 | Status check errors |
| 401-499 | Bank KYC errors |
| 501-599 | Organization KYC errors |

## Compliance

This implementation follows:
- **eSign API Specification v3.3** (CCA, India)
- **Information Technology Act, 2000**
- **e-Authentication Guidelines** (CCA)
- **Aadhaar Paperless Offline e-KYC** (UIDAI)
- **RFC 6238** (TOTP)
- **FIDO2 / WebAuthn** specifications
- **XML Signature Syntax and Processing** (W3C)

## License

Government of India - Controller of Certifying Authorities