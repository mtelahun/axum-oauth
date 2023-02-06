use crate::helpers::{spawn_app, assert_is_redirect_to};


#[tokio::test]
pub async fn register_client() {
    // Arrange
    let state = spawn_app().await;
    let client = state.api_client;

    // Act
    let response = client
        .get(&format!("{}/oauth/client", &state.app_address))
        .send()
        .await
        .expect("request to client api failed");

    // Assert
    assert_is_redirect_to(&response, "/oauth/signin?callback=client");
    
}
