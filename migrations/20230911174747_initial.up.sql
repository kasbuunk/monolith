CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS 
    users (
        id UUID PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL, 
        first_name VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL
    );
