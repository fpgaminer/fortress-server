mod auth;
mod error;

use std::net::SocketAddr;

use actix_web::{middleware::Logger, web, web::Data, App, HttpResponse, HttpServer};
use anyhow::Context;
use env_logger::Env;
use error::ServerError;
use serde::Deserialize;
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::auth::AuthenticatedUserId;


#[derive(Clone, Deserialize)]
struct Config {
	database_url: String,
	bind: SocketAddr,
}


const MAXIMUM_REQUEST_SIZE: usize = 1024 * 1024 * 10; // 10 MB


#[actix_web::main]
async fn main() -> Result<(), anyhow::Error> {
	// Env logger
	env_logger::Builder::from_env(Env::default().default_filter_or("warn,actix_web=debug,fortress_server=debug,actix_server=info")).init();

	// Read config
	let config = read_config()?;

	// Setup database
	let db_pool = setup_database(&config).await?;

	// Setup HTTP server
	let data_config = Data::new(config.clone());
	let server = HttpServer::new(move || {
		let logger = Logger::default();

		App::new()
			.wrap(logger)
			.app_data(web::PayloadConfig::default().limit(MAXIMUM_REQUEST_SIZE))
			.app_data(Data::new(db_pool.clone()))
			.app_data(data_config.clone())
			.service(get_objects)
			.service(get_object)
			.service(update_object)
			.service(user_update_login_key)
	})
	.bind(config.bind)?
	.run();

	server.await?;

	Ok(())
}


fn read_config() -> anyhow::Result<Config> {
	let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
	let config = std::fs::read_to_string(config_path).context("reading config")?;
	let config: Config = toml::from_str(&config).context("parsing config")?;

	Ok(config)
}


async fn setup_database(config: &Config) -> anyhow::Result<PgPool> {
	let db_pool = PgPoolOptions::new()
		.max_connections(5)
		.connect(&config.database_url)
		.await
		.context("connecting to database")?;

	sqlx::migrate!("./migrations").run(&db_pool).await.context("running database migrations")?;

	Ok(db_pool)
}


/// Returns a JSON encoded list of all object SIVs belonging to the user.
#[actix_web::get("/objects")]
async fn get_objects(db_pool: Data<sqlx::PgPool>, user_id: AuthenticatedUserId) -> Result<HttpResponse, ServerError> {
	let sivs: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as("SELECT object_id,siv FROM objects WHERE user_id = $1")
		.bind(user_id.0)
		.fetch_all(&**db_pool)
		.await?;

	let response = sivs.into_iter().map(|(id, siv)| (hex::encode(id), hex::encode(siv))).collect::<Vec<_>>();

	Ok(HttpResponse::Ok().json(response))
}


/// Returns an object's data.
#[actix_web::get("/object/{id}")]
async fn get_object(db_pool: Data<sqlx::PgPool>, user_id: AuthenticatedUserId, id: web::Path<String>) -> Result<HttpResponse, ServerError> {
	let id = match hex::decode(id.into_inner()) {
		Ok(id) => id,
		Err(_) => return Ok(HttpResponse::BadRequest().body("Invalid object ID")),
	};

	let data: Option<(Vec<u8>,)> = sqlx::query_as("SELECT payload FROM objects WHERE user_id = $1 AND object_id = $2")
		.bind(user_id.0)
		.bind(id)
		.fetch_optional(&**db_pool)
		.await?;

	match data {
		Some(data) => Ok(HttpResponse::Ok().body(data.0)),
		None => Ok(HttpResponse::NotFound().body("Object not found")),
	}
}


/// Create or update an object.
#[actix_web::post("/object/{id}/{old_siv}")]
async fn update_object(
	db_pool: Data<sqlx::PgPool>,
	user_id: AuthenticatedUserId,
	path: web::Path<(String, String)>,
	data: web::Bytes,
) -> Result<HttpResponse, ServerError> {
	let (id, old_siv) = path.into_inner();
	let id = match hex::decode(id) {
		Ok(id) => id,
		Err(_) => return Ok(HttpResponse::BadRequest().body("Invalid object ID")),
	};

	let old_siv = match hex::decode(old_siv) {
		Ok(old_siv) => old_siv,
		Err(_) => return Ok(HttpResponse::BadRequest().body("Invalid old SIV")),
	};

	let data = data.to_vec();

	if data.len() < 32 {
		return Ok(HttpResponse::BadRequest().body("SIV missing"));
	}

	let siv = data[data.len() - 32..].to_vec();

	// If object doesn't exist in the database, we can ignore old_siv and just insert it.
	// If it does exist, we need to check that old_siv matches the SIV in the database, before updating it.  If it doesn't match, we return an error.
	let  result = sqlx::query("INSERT INTO objects (user_id, object_id, payload, siv) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, object_id) DO UPDATE SET payload = $3, siv = $4 WHERE objects.siv = $5")
		.bind(user_id.0)
		.bind(id)
		.bind(data)
		.bind(siv)
		.bind(old_siv)
		.execute(&**db_pool)
		.await?;

	if result.rows_affected() == 0 {
		Ok(HttpResponse::Conflict().body("SIV mismatch"))
	} else {
		Ok(HttpResponse::Ok().finish())
	}
}


/// Update user login_key.
#[actix_web::post("/user/login_key")]
async fn user_update_login_key(db_pool: Data<sqlx::PgPool>, user_id: AuthenticatedUserId, login_key: web::Bytes) -> Result<HttpResponse, ServerError> {
	let login_key = login_key.to_vec();

	if login_key.len() != 32 {
		return Ok(HttpResponse::BadRequest().body("Invalid login key"));
	}

	sqlx::query("UPDATE users SET login_key = $1 WHERE id = $2")
		.bind(login_key)
		.bind(user_id.0)
		.execute(&**db_pool)
		.await?;

	Ok(HttpResponse::Ok().finish())
}


#[cfg(test)]
mod tests {
	use crate::{get_object, get_objects, read_config, setup_database, update_object, user_update_login_key};
	use actix_http::Request;
	use actix_web::{
		dev::{Service, ServiceResponse},
		test,
		web::Data,
		App,
	};
	use rand::{
		rand_core::UnwrapErr,
		rngs::SysRng,
		seq::{IndexedMutRandom, IndexedRandom},
		RngExt as _,
	};
	use std::collections::HashSet;

	struct TestObject {
		id: [u8; 32],
		data: Vec<u8>,
		siv: [u8; 32],
	}

	// TODO: I'm not a fan of duplicating the app setup code
	#[actix_web::test]
	async fn test_integration() {
		let config = read_config().unwrap();

		// Setup database
		let db_pool = setup_database(&config).await.unwrap();

		// Setup HTTP server
		let data_config = Data::new(config.clone());
		let mut app = test::init_service(
			App::new()
				.app_data(Data::new(db_pool.clone()))
				.app_data(data_config.clone())
				.service(get_objects)
				.service(get_object)
				.service(update_object)
				.service(user_update_login_key),
		)
		.await;

		// Create user
		let login_id: [u8; 32] = UnwrapErr(SysRng).random();
		let login_key: [u8; 32] = UnwrapErr(SysRng).random();
		let auth_token = [login_id, login_key].concat();

		// Insert into database
		sqlx::query("INSERT INTO users (login_id, login_key) VALUES ($1, $2)")
			.bind(login_id)
			.bind(login_key)
			.execute(&db_pool)
			.await
			.unwrap();

		// List objects (should be empty)
		let server_objects = api_get_objects(&mut app, &auth_token).await.unwrap();
		assert_eq!(server_objects, vec![]);

		// Push some objects
		let mut objects = (0..10)
			.map(|_| TestObject {
				id: UnwrapErr(SysRng).random(),
				data: (0..UnwrapErr(SysRng).random_range(0..1024)).map(|_| UnwrapErr(SysRng).random()).collect(),
				siv: UnwrapErr(SysRng).random(),
			})
			.collect::<Vec<_>>();

		for object in &objects {
			api_update_object(&mut app, &auth_token, &object.id, &[0; 32], &object.data, &object.siv)
				.await
				.unwrap();
		}

		// List objects
		let server_objects = api_get_objects(&mut app, &auth_token).await.unwrap();
		assert_eq!(
			server_objects.into_iter().collect::<HashSet<_>>(),
			objects.iter().map(|object| (object.id, object.siv)).collect::<HashSet<_>>()
		);

		// Pull their contents and verify
		for object in &objects {
			let server_data = api_get_object(&mut app, &auth_token, &object.id).await.unwrap();
			assert_eq!(server_data, [object.data.as_slice(), &object.siv].concat());
		}

		// Update an object
		let object = objects.choose_mut(&mut UnwrapErr(SysRng)).unwrap();
		let old_siv = object.siv;
		object.data = (0..UnwrapErr(SysRng).random_range(0..1024)).map(|_| UnwrapErr(SysRng).random()).collect();
		object.siv = UnwrapErr(SysRng).random();

		api_update_object(&mut app, &auth_token, &object.id, &old_siv, &object.data, &object.siv)
			.await
			.unwrap();

		// List objects to verify updated siv
		let server_objects = api_get_objects(&mut app, &auth_token).await.unwrap();
		assert_eq!(
			server_objects.into_iter().collect::<HashSet<_>>(),
			objects.iter().map(|object| (object.id, object.siv)).collect::<HashSet<_>>()
		);

		// Pull all objects and verify again
		for object in &objects {
			let server_data = api_get_object(&mut app, &auth_token, &object.id).await.unwrap();
			assert_eq!(server_data, [object.data.as_slice(), &object.siv].concat());
		}

		// Try to update an object using a bad siv
		let object = objects.choose(&mut UnwrapErr(SysRng)).unwrap();
		let bad_siv: [u8; 32] = UnwrapErr(SysRng).random();

		assert_eq!(
			api_update_object(&mut app, &auth_token, &object.id, &bad_siv, &object.data, &object.siv)
				.await
				.unwrap_err(),
			409
		);

		// Make sure APIs fail with missing auth header
		let object = objects.choose(&mut UnwrapErr(SysRng)).unwrap();

		assert_eq!(test::TestRequest::get().uri("/objects").send_request(&mut app).await.status(), 401);

		assert_eq!(
			test::TestRequest::get()
				.uri(&format!("/object/{}", hex::encode(&object.id)))
				.send_request(&mut app)
				.await
				.status(),
			401
		);

		assert_eq!(
			test::TestRequest::post()
				.uri(&format!("/object/{}/{}", hex::encode(&object.id), hex::encode(&object.siv)))
				.send_request(&mut app)
				.await
				.status(),
			401
		);

		assert_eq!(test::TestRequest::post().uri("/user/login_key").send_request(&mut app).await.status(), 401);

		// Make sure APIs fail with bad LoginKey
		let bad_login_key: [u8; 32] = UnwrapErr(SysRng).random();
		let bad_auth_token = [login_id, bad_login_key].concat();

		assert_eq!(api_get_objects(&mut app, &bad_auth_token).await.unwrap_err(), 401);
		assert_eq!(api_get_object(&mut app, &bad_auth_token, &object.id).await.unwrap_err(), 401);
		assert_eq!(
			api_update_object(&mut app, &bad_auth_token, &object.id, &object.siv, &object.data, &object.siv)
				.await
				.unwrap_err(),
			401
		);
		assert_eq!(api_update_login_key(&mut app, &bad_auth_token, &login_key).await.unwrap_err(), 401);

		// Make sure APIs fail with bad LoginID
		let bad_login_id: [u8; 32] = UnwrapErr(SysRng).random();
		let bad_auth_token = [bad_login_id, login_key].concat();

		assert_eq!(api_get_objects(&mut app, &bad_auth_token).await.unwrap_err(), 401);
		assert_eq!(api_get_object(&mut app, &bad_auth_token, &object.id).await.unwrap_err(), 401);
		assert_eq!(
			api_update_object(&mut app, &bad_auth_token, &object.id, &object.siv, &object.data, &object.siv)
				.await
				.unwrap_err(),
			401
		);
		assert_eq!(api_update_login_key(&mut app, &bad_auth_token, &login_key).await.unwrap_err(), 401);

		// Test LoginKey change
		let login_key: [u8; 32] = UnwrapErr(SysRng).random();
		let old_auth_token = auth_token.clone();

		api_update_login_key(&mut app, &auth_token, &login_key).await.unwrap();
		let auth_token = [login_id, login_key].concat();

		// Make sure APIs fail with old LoginKey
		assert_eq!(api_get_objects(&mut app, &old_auth_token).await.unwrap_err(), 401);
		assert_eq!(api_get_object(&mut app, &old_auth_token, &object.id).await.unwrap_err(), 401);
		assert_eq!(
			api_update_object(&mut app, &old_auth_token, &object.id, &object.siv, &object.data, &object.siv)
				.await
				.unwrap_err(),
			401
		);
		assert_eq!(api_update_login_key(&mut app, &old_auth_token, &login_key).await.unwrap_err(), 401);

		// Make sure APIs succeed with new LoginKey
		api_get_objects(&mut app, &auth_token).await.unwrap();
	}

	async fn api_get_objects<S, B, E>(app: &mut S, auth_token: &[u8]) -> Result<Vec<([u8; 32], [u8; 32])>, u16>
	where
		S: Service<Request, Response = ServiceResponse<B>, Error = E>,
		E: std::fmt::Debug,
		B: actix_http::body::MessageBody,
	{
		let res = test::TestRequest::get()
			.uri("/objects")
			.insert_header(("Authorization", format!("Bearer {}", hex::encode(auth_token))))
			.send_request(app)
			.await;

		if !res.status().is_success() {
			return Err(res.status().as_u16());
		}

		let body: Vec<(String, String)> = test::read_body_json(res).await;

		Ok(body
			.into_iter()
			.map(|(id, siv)| (hex::decode(id).unwrap().try_into().unwrap(), hex::decode(siv).unwrap().try_into().unwrap()))
			.collect())
	}

	async fn api_get_object<S, B, E>(app: &mut S, auth_token: &[u8], id: &[u8]) -> Result<Vec<u8>, u16>
	where
		S: Service<Request, Response = ServiceResponse<B>, Error = E>,
		E: std::fmt::Debug,
		B: actix_http::body::MessageBody,
	{
		let res = test::TestRequest::get()
			.uri(&format!("/object/{}", hex::encode(id)))
			.insert_header(("Authorization", format!("Bearer {}", hex::encode(auth_token))))
			.send_request(app)
			.await;

		if !res.status().is_success() {
			return Err(res.status().as_u16());
		}

		Ok(test::read_body(res).await.to_vec())
	}

	async fn api_update_object<S, B, E>(app: &mut S, auth_token: &[u8], id: &[u8], old_siv: &[u8], data: &[u8], siv: &[u8]) -> Result<(), u16>
	where
		S: Service<Request, Response = ServiceResponse<B>, Error = E>,
		E: std::fmt::Debug,
		B: actix_http::body::MessageBody,
	{
		let data_and_siv = [data, siv].concat();

		let res = test::TestRequest::post()
			.uri(&format!("/object/{}/{}", hex::encode(id), hex::encode(old_siv)))
			.insert_header(("Authorization", format!("Bearer {}", hex::encode(auth_token))))
			.set_payload(data_and_siv)
			.send_request(app)
			.await;

		if !res.status().is_success() {
			return Err(res.status().as_u16());
		}

		Ok(())
	}

	async fn api_update_login_key<S, B, E>(app: &mut S, auth_token: &[u8], new_login_key: &[u8]) -> Result<(), u16>
	where
		S: Service<Request, Response = ServiceResponse<B>, Error = E>,
		E: std::fmt::Debug,
		B: actix_http::body::MessageBody,
	{
		let res = test::TestRequest::post()
			.uri("/user/login_key")
			.insert_header(("Authorization", format!("Bearer {}", hex::encode(auth_token))))
			.set_payload(new_login_key.to_vec())
			.send_request(app)
			.await;

		if !res.status().is_success() {
			return Err(res.status().as_u16());
		}

		Ok(())
	}
}
