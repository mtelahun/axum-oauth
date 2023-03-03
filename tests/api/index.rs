use crate::helpers::{assert_is_redirect_to, spawn_app, ClientType};

#[tokio::test]
pub async fn index_not_found() {
    // Arrange
    let state = spawn_app().await;
    let client = reqwest::Client::new();

    // Act
    let response = client
        .get(&format!("{}/", &state.app_address))
        .send()
        .await
        .expect("request to client api failed");

    // Assert
    assert_eq!(
        response.status().as_u16(),
        404,
        "Getting index (https://foo/) returns 404 Not Found"
    )
}

#[tokio::test]
pub async fn oauth_index_redirect_to_sign_in() {
    // Arrange
    let state = spawn_app().await;
    let client = state.api_client;

    // Act
    let response = client
        .get(&format!("{}/oauth", &state.app_address))
        .send()
        .await
        .expect("request to client api failed");

    // Assert
    assert_is_redirect_to(&response, 303, "/oauth/signin?callback=", false);
}

#[tokio::test]
pub async fn oauth_index_happy_path() {
    // Arrange
    let mut state = spawn_app().await;
    let params = serde_json::json!({
        "name": "foo client",
        "redirect_uri": "http://localhost:3001/endpoint",
        "type": "confidential",
    });
    let client_id = state
        .register_client(&params, ClientType::Confidential)
        .await;
    state.signin("foo", "secret").await;
    state.authorization_flow(&client_id).await;

    // Act
    let client = state.api_client;
    let response = client
        .get(&format!("{}/oauth/", &state.app_address))
        .bearer_auth(state.token.access_token.unwrap())
        .send()
        .await
        .expect("request to client api failed");

    // Assert
    let status = response.status().as_u16();
    let body = response
        .text()
        .await
        .expect("Unable to decode response body");
    tracing::debug!("Body: {}", body);
    assert_eq!(status, 200, "OAuth root returned successfully");
    assert!(
        body.contains("foo client"),
        "Client list contains the newly registerd client."
    );
}
