# Fortress Server

Fortress Server is the sync server for the Fortress password manager.


## API

Authorization header required for all requests.  It must contain the hex encoded 32 byte LoginId followed by the hex encoded 32 byte LoginKey (total 128 characters).

### `GET /objects`

Returns a list of all objects in the database belonging to the user.  The response is a JSON array where each element is an array of the form `[id, siv]`, and both are hex encoded.

### `GET /object/:id`

Returns the object's data. ID is hex encoded.

### `POST /object/:id/:old_siv`

Creates or updates an object. The request body is the object's data (including the SIV).  `:id` and `:old_siv` are hex encoded.  If the object already exists, `:old_siv` must match the object's current SIV.  If the object does not exist, `:old_siv` is ignored.  Conflict (409) is returned if the object already exists and `:old_siv` does not match the object's current SIV.  This is to prevent overwriting an object that has been updated since the last time the client fetched it.


## Run locally

	./run-test-db.sh
	cargo run


## Run tests

	./run-test-db.sh
	cargo test


## Build docker image

	docker build -t fortress-server .
	docker tag fortress-server DEST
	docker push DEST