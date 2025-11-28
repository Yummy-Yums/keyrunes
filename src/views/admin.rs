use axum::{
    extract::Extension,
    response::{Html, IntoResponse},
};
use tera::Tera;

use crate::handler::auth::AuthenticatedUser;

pub async fn admin_page(
    Extension(user): Extension<AuthenticatedUser>,
    Extension(tera): Extension<Tera>,
) -> impl IntoResponse {
    // Check if user is superadmin
    if !user.groups.contains(&"superadmin".to_string()) {
        return Html("<h1>403 Forbidden</h1><p>Superadmin access required</p>".to_string())
            .into_response();
    }

    let mut context = tera::Context::new();
    context.insert("user", &serde_json::json!({
        "user_id": user.user_id,
        "username": user.username,
        "email": user.email,
        "groups": user.groups,
    }));

    match tera.render("admin.html", &context) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template error: {}", e);
            Html(format!("<h1>Error rendering template</h1><p>{}</p>", e)).into_response()
        }
    }
}
