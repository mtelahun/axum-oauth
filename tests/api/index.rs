use crate::helpers::{spawn_app, assert_is_redirect_to};

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
