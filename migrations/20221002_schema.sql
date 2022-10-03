CREATE TABLE IF NOT EXISTS users (
	id serial PRIMARY KEY,
	login_id bytea NOT NULL UNIQUE,
	login_key bytea NOT NULL
);


CREATE TABLE IF NOT EXISTS objects (
	user_id integer NOT NULL,
	object_id bytea NOT NULL,
	payload bytea NOT NULL,
	siv bytea NOT NULL,
	PRIMARY KEY (user_id, object_id)
);
CREATE INDEX IF NOT EXISTS objects_user_id_idx ON objects (user_id);