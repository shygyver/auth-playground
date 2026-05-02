#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    \c oidc;

    CREATE TABLE IF NOT EXISTS private_keys
    (
        key_id character varying(255) NOT NULL,
        id integer NOT NULL DEFAULT 1,
        private_key text NOT NULL,
        wrapped_dek text NOT NULL,
        expires_at timestamp with time zone NOT NULL,
        created_at timestamp with time zone NOT NULL DEFAULT now(),
        CONSTRAINT private_keys_pkey PRIMARY KEY (key_id),
        CONSTRAINT private_keys_id_unique UNIQUE (id),
        CONSTRAINT id CHECK (id = 1)
    );

    CREATE TABLE IF NOT EXISTS public_keys
    (
        key_id character varying(255) NOT NULL,
        public_key text NOT NULL,
        expires_at timestamp with time zone NOT NULL,
        created_at timestamp with time zone NOT NULL DEFAULT now(),
        CONSTRAINT public_keys_pkey PRIMARY KEY (key_id)
    );
EOSQL