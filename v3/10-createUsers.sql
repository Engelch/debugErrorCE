-- DROP PROCEDURE add_user(character varying,character varying);

CREATE OR REPLACE PROCEDURE add_user(IN username text, IN xxx text)
LANGUAGE plpgsql
as $$
BEGIN
    IF EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE  rolname = username
      ) 
    THEN
        RAISE NOTICE 'Skipping. Role already exists:%', username;
    ELSE
        begin
            raise notice $u$creating role %$u$, username;
            -- table names are special => create role username => create role username no replacement of username
            -- dynamic sql must be used with execute
            -- %L inserts the xxx with single quotes. %I would be double-quotes.
            execute format('create role %s login password  %L', username, xxx);
        end;
    END IF;
END;
$$;

CREATE OR REPLACE PROCEDURE add_superuser(username IN varchar, psswrd IN varchar)
LANGUAGE plpgsql
as $$
BEGIN
    IF EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE  rolname = username
      ) 
    THEN
        RAISE NOTICE 'Skipping. Role already exists:%', username;
    ELSE
        raise notice 'creating superuser role %', username;
        execute format('create role %s login superuser password  %L', username, xxx);
    END IF;
END;
$$;

do
$$
BEGIN
    call add_user('psqltestro','psqlTestRO_PW_8383020');
    call add_user('psqltestrw','psqlTestRW_PW_83830389');
    call add_user('psqltestrwd','psqlTestRWD_PW_83xxa0389');
    call add_user('psqltestrwdt','psqlTestRWDT_PW_838xs3389');
    call add_superuser('spostgres','demoPW837378_8372');
END;
$$;
