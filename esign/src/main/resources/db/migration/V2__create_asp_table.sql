-- ASP registry: registered Authentication Service Providers
CREATE TABLE asps (
    id UUID NOT NULL PRIMARY KEY,
    asp_id VARCHAR(100) NOT NULL,
    organisation_name VARCHAR(200) NOT NULL,
    contact_email VARCHAR(200),
    contact_phone VARCHAR(30),
    certificate_pem TEXT,
    allowed_response_url_prefix VARCHAR(500),
    status VARCHAR(20) NOT NULL check (status in ('ACTIVE','INACTIVE','SUSPENDED')),
    notes TEXT,
    registered_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,
    CONSTRAINT uk_asp_id UNIQUE (asp_id)
);

CREATE INDEX idx_asp_status ON asps (status);