#!/bin/sh
docker run --rm -it -p 5432:5432 -e PGDATA=/var/lib/postgresql/data/pgdata -v `pwd`/testdb:/var/lib/postgresql/data -e POSTGRES_PASSWORD=test postgres:14