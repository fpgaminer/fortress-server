use std::pin::Pin;

use actix_web::{
	dev::Payload,
	error::{ErrorInternalServerError, ErrorUnauthorized},
	web, Error, FromRequest, HttpRequest,
};
use sqlx::PgPool;
use std::future::Future;
use subtle::ConstantTimeEq;


pub struct AuthenticatedUserId(pub i32);

// Pulls the Authorization header from the request and, using the database, validates it, returning the user's ID if valid.
// If any errors occur (except for database errors, which return 500), a 401 Unauthorized is returned.
// TODO: Log the database error if it occurs.
impl FromRequest for AuthenticatedUserId {
	type Error = Error;
	type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

	fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
		let req = req.clone();
		Box::pin(async move {
			let db_pool = req
				.app_data::<PgPool>()
				.or_else(|| req.app_data::<web::Data<PgPool>>().map(|d| d.as_ref()))
				.expect("Missing PgPool");

			let token = req
				.headers()
				.get("Authorization")
				.and_then(|auth| auth.to_str().ok())
				// Skip "Bearer"
				.and_then(|auth| auth.split(' ').nth(1))
				// Decode as hex
				.and_then(|auth| {
					let mut token = [0u8; 64];
					hex::decode_to_slice(auth, &mut token).ok()?;
					Some(token)
				})
				.ok_or_else(|| ErrorUnauthorized("Invalid Authorization Header"))?;

			let (login_id, login_key) = token.split_at(32);

			// Fetch the correct login_key from the database
			let (server_user_id, server_login_key): (i32, Vec<u8>) = sqlx::query_as("SELECT id,login_key FROM users WHERE login_id = $1")
				.bind(login_id)
				.fetch_optional(db_pool)
				.await
				.map_err(|_| ErrorInternalServerError("Internal Server Error"))?
				.ok_or_else(|| ErrorUnauthorized("Invalid Authorization Header"))?;

			// Constant time compare
			if !bool::from(server_login_key.ct_eq(login_key)) {
				return Err(ErrorUnauthorized("Invalid Authorization Header"));
			}

			Ok(Self(server_user_id))
		})
	}
}
