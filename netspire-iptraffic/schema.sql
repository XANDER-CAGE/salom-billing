-- Drop schema objects

DROP TABLE IF EXISTS contract_info;
DROP TABLE IF EXISTS contract_info_items;
DROP TABLE IF EXISTS admins;
DROP TABLE IF EXISTS session_details;
DROP TABLE IF EXISTS iptraffic_sessions;
DROP TABLE IF EXISTS assigned_radius_replies;
DROP TABLE IF EXISTS radius_replies;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS fin_transactions;
DROP TABLE IF EXISTS contracts;
DROP TABLE IF EXISTS contract_kinds;
DROP TABLE IF EXISTS plans;
DROP TABLE IF EXISTS currencies_rate;
DROP TABLE IF EXISTS currencies;

DROP SEQUENCE IF EXISTS iptraffic_sessions_id_seq CASCADE;
DROP SEQUENCE IF EXISTS assigned_radius_replies_id_seq CASCADE;
DROP SEQUENCE IF EXISTS radius_replies_id_seq CASCADE;

CREATE SEQUENCE radius_replies_id_seq;
CREATE SEQUENCE assigned_radius_replies_id_seq;
CREATE SEQUENCE iptraffic_sessions_id_seq;

CREATE TABLE currencies (
       id INTEGER PRIMARY KEY,
       short_name VARCHAR(10) UNIQUE NOT NULL,
       name VARCHAR(100) UNIQUE NOT NULL,
       description VARCHAR(200) NOT NULL
);

-- to convert from_id currency to to_id, one should follow formula:
-- from_amount * rate = to_amount
CREATE TABLE currencies_rate (
       from_id INTEGER REFERENCES currencies(id),
       to_id INTEGER REFERENCES currencies(id),
       rate NUMERIC(20, 10) NOT NULL,
       PRIMARY KEY (from_id, to_id)
);

DROP SEQUENCE IF EXISTS plans_id_seq CASCADE;
CREATE SEQUENCE plans_id_seq;
CREATE TABLE plans(
    id INTEGER NOT NULL DEFAULT NEXTVAL('plans_id_seq') PRIMARY KEY,
    name VARCHAR NOT NULL UNIQUE,
    code VARCHAR NOT NULL UNIQUE,
    currency_id INTEGER NOT NULL REFERENCES currencies(id),
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE,
    auth_algo VARCHAR NOT NULL,
    acct_algo VARCHAR NOT NULL,
    settings VARCHAR NOT NULL
);

DROP SEQUENCE IF EXISTS contract_kinds_id_seq;
CREATE SEQUENCE contract_kinds_id_seq;
CREATE TABLE contract_kinds (
    id INTEGER DEFAULT NEXTVAL('contract_kinds_id_seq') PRIMARY KEY,
    kind_name VARCHAR NOT NULL UNIQUE,
    description VARCHAR NOT NULL DEFAULT ''
);

DROP SEQUENCE IF EXISTS contracts_id_seq CASCADE;
CREATE SEQUENCE contracts_id_seq;
CREATE TABLE contracts (
    id INTEGER NOT NULL DEFAULT NEXTVAL('contracts_id_seq') UNIQUE,
    kind_id INTEGER NOT NULL REFERENCES contract_kinds(id),
    balance NUMERIC(20,10) NOT NULL DEFAULT 0.0,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    currency_id INTEGER NOT NULL REFERENCES currencies(id),
    PRIMARY KEY (id, kind_id)
);

DROP SEQUENCE IF EXISTS fin_transactions_id_seq CASCADE;
CREATE SEQUENCE fin_transactions_id_seq;
CREATE TABLE fin_transactions (
    id INTEGER NOT NULL DEFAULT NEXTVAL('fin_transactions_id_seq') PRIMARY KEY,
    kind_id INTEGER NOT NULL,
    contract_id INTEGER NOT NULL,
    currency_id INTEGER NOT NULL REFERENCES currencies (id),
    amount NUMERIC(20,10) NOT NULL,
    amount_in_contract_currency NUMERIC(20,10) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    balance_after NUMERIC(20,10) NOT NULL,
    comment VARCHAR NOT NULL,
    FOREIGN KEY (kind_id, contract_id) REFERENCES contracts (kind_id, id)
);

DROP SEQUENCE IF EXISTS accounts_id_seq;
CREATE SEQUENCE accounts_id_seq;
CREATE TABLE accounts (
    id INTEGER NOT NULL DEFAULT NEXTVAL('accounts_id_seq') PRIMARY KEY,
    contract_id INTEGER NOT NULL REFERENCES contracts(id),
    plan_id INTEGER NOT NULL REFERENCES plans(id),
    login VARCHAR(128) NOT NULL UNIQUE,
    password VARCHAR(128) NOT NULL,
    active BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    plan_data VARCHAR NOT NULL DEFAULT ''
);

CREATE TABLE radius_replies(
    id INTEGER NOT NULL DEFAULT NEXTVAL('radius_replies_id_seq') PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE assigned_radius_replies(
    id INTEGER NOT NULL DEFAULT NEXTVAL('assigned_radius_replies_id_seq') PRIMARY KEY,
    target_id INTEGER NOT NULL,
    target_type VARCHAR(128) NOT NULL,
    radius_reply_id INTEGER NOT NULL REFERENCES radius_replies(id),
    value VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE iptraffic_sessions(
    id INTEGER NOT NULL DEFAULT NEXTVAL('iptraffic_sessions_id_seq') PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    sid VARCHAR(128) NOT NULL,
    cid VARCHAR(128),
    ip VARCHAR(128) NOT NULL,
    octets_in BIGINT DEFAULT 0,
    octets_out BIGINT DEFAULT 0,
    amount NUMERIC(20,10) DEFAULT 0.0,
    started_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE,
    finished_at TIMESTAMP WITHOUT TIME ZONE,
    expired BOOLEAN
);

CREATE INDEX ON iptraffic_sessions (account_id, sid);

CREATE TABLE session_details (
    id INTEGER REFERENCES iptraffic_sessions,
    traffic_class VARCHAR(128) NOT NULL,
    octets_in BIGINT NOT NULL DEFAULT 0,
    octets_out BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id, traffic_class)
);


DROP SEQUENCE IF EXISTS admins_id_seq;
CREATE SEQUENCE admins_id_seq;
CREATE TABLE admins (
    id INTEGER NOT NULL DEFAULT NEXTVAL('admins_id_seq') PRIMARY KEY,
    email VARCHAR NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    password VARCHAR NOT NULL,
    real_name VARCHAR NOT NULL,
    created_at DATE NOT NULL DEFAULT CURRENT_DATE,
    roles VARCHAR NOT NULL
);

DROP SEQUENCE IF EXISTS contract_info_items_seq;
CREATE SEQUENCE contract_info_items_seq;
CREATE TABLE contract_info_items (
    kind_id INTEGER NOT NULL REFERENCES contract_kinds(id),
    id INTEGER DEFAULT NEXTVAL('contract_info_items_seq') NOT NULL,
    sort_order INTEGER NOT NULL,
    field_name VARCHAR NOT NULL UNIQUE,
    field_description VARCHAR NOT NULL DEFAULT '',
    PRIMARY KEY (kind_id, id)
);

DROP SEQUENCE IF EXISTS contract_info_seq;
CREATE SEQUENCE contract_info_seq;
CREATE TABLE contract_info (
    id INTEGER DEFAULT NEXTVAL('contract_info_seq') PRIMARY KEY,
    kind_id INTEGER NOT NULL,
    contract_id INTEGER NOT NULL,
    info_id INTEGER NOT NULL,
    info_value VARCHAR NOT NULL DEFAULT '',
    FOREIGN KEY (kind_id, info_id) REFERENCES contract_info_items (kind_id, id),
    FOREIGN KEY (kind_id, contract_id) REFERENCES contracts (kind_id, id)
);

CREATE OR REPLACE FUNCTION credit_transaction
    (account_id INTEGER, amount NUMERIC(20, 10), comment VARCHAR, currency_id INTEGER)
    RETURNS NUMERIC(20, 10) AS $$
BEGIN
    IF amount < 0 THEN
        RAISE 'Attempt to perform negative credit: account %, amount %, comment %, currency_id %', account_id, amount, comment, currency_id;
    END IF;
    RETURN make_transaction(account_id, amount, comment, currency_id);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION debit_transaction
    (account_id INTEGER, amount NUMERIC(20, 10), comment VARCHAR, currency_id INTEGER)
    RETURNS NUMERIC(20, 10) AS $$
BEGIN
    IF amount < 0 THEN
        RAISE 'Attempt to perform negative debit: account %, amount %, comment %, currency_id %', account_id, amount, comment, currency_id;
    END IF;
    RETURN make_transaction(account_id, -amount, comment, currency_id);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION make_transaction
    (account_id INTEGER, amount NUMERIC(20, 10), comment VARCHAR, currency_id INTEGER)
    RETURNS NUMERIC(20, 10) AS $$
DECLARE
    contract_currency_id INTEGER;
    contract_id INTEGER;
    kind_id INTEGER;
    new_balance NUMERIC(20, 10);
    true_amount NUMERIC(20, 10);
BEGIN
    SELECT c.id, c.kind_id, c.currency_id
        INTO contract_id, kind_id, contract_currency_id
	FROM contracts c, accounts a
        WHERE a.id = account_id AND a.contract_id = c.id;
    true_amount := amount;
    IF currency_id IS NULL THEN
        currency_id := contract_currency_id;
    END IF;
    IF currency_id <> contract_currency_id AND amount < 0 THEN
        RAISE 'Attempt to perform a debit operation for account %, amount %, comment %, currency_id % while contract is in currency %',
	    account_id, amount, comment, currency_id, contract_currency;
    END IF;
    IF currency_id <> contract_currency_id THEN
        SELECT amount * rate
	    INTO true_amount
	    FROM currencies_rate
	    WHERE from_id = currency_id AND to_id = contract_currency_id;
	IF NOT FOUND THEN
	    SELECT amount / rate
	        INTO true_amount
		FROM currencies_rate
		WHERE from_id = contract_currency_id AND to_id = currency_id;
	    IF NOT FOUND THEN
	        RAISE 'Cannot convert between % and % currencies', contract_currency_id, currency_id;
	    END IF;
	END IF;
    END IF;
    IF true_amount <> 0 THEN
        UPDATE contracts SET balance = balance + true_amount WHERE id = contract_id
	    RETURNING balance INTO new_balance;
	INSERT INTO fin_transactions
            (kind_id, contract_id, currency_id, amount, amount_in_contract_currency,
	     created_at, balance_after, comment)
	    VALUES (kind_id, contract_id, currency_id, amount, true_amount,
	    	    NOW() AT TIME ZONE 'UTC',
		    new_balance, comment);
	RETURN new_balance;
    ELSE
        SELECT balance INTO new_balance FROM contracts WHERE id = contract_id;
	RETURN new_balance;
    END IF;
END;
$$ LANGUAGE plpgsql;
