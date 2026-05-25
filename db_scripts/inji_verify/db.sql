CREATE DATABASE :mosipdbname
	ENCODING = 'UTF8'
	LC_COLLATE = 'en_US.UTF-8'
	LC_CTYPE = 'en_US.UTF-8'
	TABLESPACE = pg_default
	OWNER = postgres
	TEMPLATE  = template0;

COMMENT ON DATABASE :mosipdbname IS 'Inji Verify related data is stored in this database';

\c :mosipdbname postgres

DROP SCHEMA IF EXISTS verify CASCADE;
CREATE SCHEMA verify;
ALTER SCHEMA verify OWNER TO postgres;
ALTER DATABASE :mosipdbname SET search_path TO verify,pg_catalog,public;
