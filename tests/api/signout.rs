use crate::helpers::{spawn_app, ClientType};

#[tokio::test]
async fn signout_ok() {
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
    state.signin("bob", "secret").await;
    state.authorization_flow(&client_id).await;

    // Act
    let client = state.api_client;
    let response = client
        .post(&format!("{}/oauth/signout/", &state.app_address))
        .bearer_auth(state.token.access_token.unwrap())
        .send()
        .await
        .expect("request to client api failed");

    // Assert
    assert_eq!(
        response.status(),
        200,
        "signout from session returns 200 Ok"
    );
}
