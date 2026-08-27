-- eSign API Database Schema v3.3
-- Initial migration for eSign and eKYC tables

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- eSign Transactions Table
CREATE TABLE esign_transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    transaction_id VARCHAR(100) NOT NULL UNIQUE,
    asp_id VARCHAR(100) NOT NULL,
    signer_id VARCHAR(200),
    version VARCHAR(10) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    max_wait_period INTEGER NOT NULL,
    response_url VARCHAR(500) NOT NULL,
    redirect_url VARCHAR(500),
    signing_algorithm VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,
    response_code VARCHAR(100),
    error_code VARCHAR(10),
    error_message VARCHAR(500),
    user_certificate TEXT,
    esp_signature TEXT,
    request_xml TEXT,
    response_xml TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE INDEX idx_esign_txn_id ON esign_transactions(transaction_id);
CREATE INDEX idx_esign_asp_id ON esign_transactions(asp_id);
CREATE INDEX idx_esign_signer_id ON esign_transactions(signer_id);
CREATE INDEX idx_esign_status ON esign_transactions(status);
CREATE INDEX idx_esign_created_at ON esign_transactions(created_at);

-- Document Signatures Table
CREATE TABLE document_signatures (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    transaction_id UUID NOT NULL REFERENCES esign_transactions(id) ON DELETE CASCADE,
    document_id INTEGER NOT NULL,
    hash_algorithm VARCHAR(20) NOT NULL,
    doc_info VARCHAR(100),
    doc_url VARCHAR(500),
    response_sig_type VARCHAR(20) NOT NULL,
    document_hash TEXT NOT NULL,
    signature_value TEXT,
    error_code VARCHAR(10),
    signed_at TIMESTAMP
);

CREATE INDEX idx_doc_sig_txn_id ON document_signatures(transaction_id);
CREATE INDEX idx_doc_sig_doc_id ON document_signatures(document_id);

-- eKYC Users Table
CREATE TABLE ekyc_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) NOT NULL UNIQUE,
    pin_hash VARCHAR(255) NOT NULL,
    pin_salt VARCHAR(255) NOT NULL,
    name VARCHAR(200) NOT NULL,
    mobile VARCHAR(20) NOT NULL UNIQUE,
    email VARCHAR(100),
    address TEXT,
    state_province VARCHAR(100),
    country VARCHAR(2),
    postal_code VARCHAR(20),
    photograph TEXT,
    dob DATE,
    gender VARCHAR(1),
    pan VARCHAR(20) UNIQUE,
    aadhaar_last4 VARCHAR(4),
    ekyc_type VARCHAR(30) NOT NULL,
    status VARCHAR(20) NOT NULL,
    ca_officer VARCHAR(200),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    activated_at TIMESTAMP,
    deactivated_at TIMESTAMP
);

CREATE INDEX idx_ekyc_username ON ekyc_users(username);
CREATE INDEX idx_ekyc_mobile ON ekyc_users(mobile);
CREATE INDEX idx_ekyc_pan ON ekyc_users(pan);
CREATE INDEX idx_ekyc_email ON ekyc_users(email);
CREATE INDEX idx_ekyc_status ON ekyc_users(status);
CREATE INDEX idx_ekyc_ekyc_type ON ekyc_users(ekyc_type);

-- User Authentication Factors Table
CREATE TABLE user_authentication_factors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES ekyc_users(id) ON DELETE CASCADE,
    factor_type VARCHAR(20) NOT NULL,
    factor_data TEXT,
    secret_key VARCHAR(255),
    public_key TEXT,
    credential_id VARCHAR(255),
    device_info TEXT,
    status VARCHAR(20) NOT NULL,
    registered_at TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    counter BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX idx_auth_factor_user_id ON user_authentication_factors(user_id);
CREATE INDEX idx_auth_factor_type ON user_authentication_factors(factor_type);
CREATE INDEX idx_auth_factor_status ON user_authentication_factors(status);
CREATE INDEX idx_auth_factor_credential_id ON user_authentication_factors(credential_id);

-- Authentication Logs Table
CREATE TABLE authentication_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES ekyc_users(id) ON DELETE CASCADE,
    transaction_id VARCHAR(100),
    factor_type VARCHAR(20) NOT NULL,
    auth_mode VARCHAR(20) NOT NULL,
    success BOOLEAN NOT NULL,
    error_code VARCHAR(10),
    error_message VARCHAR(500),
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_auth_log_user_id ON authentication_logs(user_id);
CREATE INDEX idx_auth_log_txn_id ON authentication_logs(transaction_id);
CREATE INDEX idx_auth_log_created_at ON authentication_logs(created_at);
CREATE INDEX idx_auth_log_success ON authentication_logs(success);

-- Organisations Table
CREATE TABLE organisations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(200) NOT NULL UNIQUE,
    address TEXT,
    kyc_org_id VARCHAR(100) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL,
    ca_officer VARCHAR(200),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    verified_at TIMESTAMP
);

CREATE INDEX idx_org_name ON organisations(name);
CREATE INDEX idx_org_kyc_id ON organisations(kyc_org_id);
CREATE INDEX idx_org_status ON organisations(status);

-- Authorised Signatories Table
CREATE TABLE authorised_signatories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    org_sig_id VARCHAR(100) NOT NULL UNIQUE,
    org_unit VARCHAR(100),
    cert_id VARCHAR(200) UNIQUE,
    certificate TEXT,
    status VARCHAR(20) NOT NULL,
    ca_officer VARCHAR(200),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    verified_at TIMESTAMP
);

CREATE INDEX idx_auth_sig_org_id ON authorised_signatories(organisation_id);
CREATE INDEX idx_auth_sig_orgsig_id ON authorised_signatories(org_sig_id);
CREATE INDEX idx_auth_sig_cert_id ON authorised_signatories(cert_id);
CREATE INDEX idx_auth_sig_status ON authorised_signatories(status);

-- Bank KYC Table
CREATE TABLE bank_kyc (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    transaction_id VARCHAR(100) NOT NULL UNIQUE,
    bank_ifsc_code VARCHAR(11),
    bank_name VARCHAR(200) NOT NULL,
    account_number VARCHAR(50) NOT NULL,
    name VARCHAR(200) NOT NULL,
    mobile VARCHAR(20) NOT NULL,
    email VARCHAR(100),
    address TEXT,
    state_province VARCHAR(100),
    country VARCHAR(2),
    postal_code VARCHAR(20),
    date_of_birth DATE,
    gender VARCHAR(1),
    pan VARCHAR(20),
    aadhaar_last4 VARCHAR(4),
    photo TEXT,
    photo_format VARCHAR(10),
    bank_signature TEXT,
    status VARCHAR(20) NOT NULL,
    response_code VARCHAR(100),
    error_code VARCHAR(10),
    error_message VARCHAR(500),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    processed_at TIMESTAMP
);

CREATE INDEX idx_bank_kyc_txn_id ON bank_kyc(transaction_id);
CREATE INDEX idx_bank_kyc_account ON bank_kyc(account_number);
CREATE INDEX idx_bank_kyc_ifsc ON bank_kyc(bank_ifsc_code);
CREATE INDEX idx_bank_kyc_status ON bank_kyc(status);