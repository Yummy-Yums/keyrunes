use axum::{
    extract::Extension,
    response::{Html, IntoResponse, Redirect},
};
use tera::Tera;

use crate::constants::{ADMIN_GROUP, SUPERADMIN_GROUP};
use crate::handler::auth::AuthenticatedUser;

pub async fn admin_page(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(tera): Extension<Tera>,
    Extension(_pool): Extension<sqlx::PgPool>,
) -> impl IntoResponse {
    if !user.groups.contains(&SUPERADMIN_GROUP.to_string())
        && !user.groups.contains(&ADMIN_GROUP.to_string())
    {
        return Redirect::to("/dashboard").into_response();
    }

    let mut context = tera::Context::new();
    context.insert(
        "user",
        &serde_json::json!({
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "groups": user.groups,
            "namespace": user.namespace,
            "organization_id": user.organization_id,
        }),
    );

    match tera.render("admin.html", &context) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template error: {}", e);
            Html(format!("<h1>Error rendering template</h1><p>{}</p>", e)).into_response()
        }
    }
}
