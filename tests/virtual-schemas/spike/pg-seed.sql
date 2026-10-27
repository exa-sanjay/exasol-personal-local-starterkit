-- Test source for the Phase-1 spike: one mixed-case table, one plain one.
CREATE DATABASE spike;
\c spike
CREATE USER spike WITH PASSWORD :'pw';
CREATE SCHEMA sales AUTHORIZATION spike;
SET ROLE spike;
CREATE TABLE sales."Orders" (
    "OrderId"   integer PRIMARY KEY,
    "Customer"  text,
    amount      numeric(12,2),
    "createdAt" timestamptz DEFAULT now()
);
INSERT INTO sales."Orders" ("OrderId", "Customer", amount) VALUES
    (1, 'Acme', 120.50), (2, 'Globex', 99.99), (3, 'Initech', 15.00);
CREATE TABLE sales.plain_t (id integer, label text);
INSERT INTO sales.plain_t VALUES (1, 'one'), (2, 'two');
