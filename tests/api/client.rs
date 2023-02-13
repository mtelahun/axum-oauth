use serde::{Deserialize, Serialize};

use crate::helpers::{spawn_app, assert_is_redirect_to};
#[derive(Debug, Deserialize)]
struct ClientResponse {
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Serialize)]
struct AuthorizationQuery {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    response_type: String,
}

#[tokio::test]
pub async fn register_client_get_form() {
    // Arrange
    let state = spawn_app().await;
    let client = state.api_client;

    // Act
    let response = client
        .get(&format!("{}/oauth/client", &state.app_address))
        .send()
        .await
        .expect("request to server api failed");

    // Assert
    assert_eq!(
        response.status().as_u16(),
        200,
        "client registration form loads successfully"
    );
    let text = response
        .text()
        .await
        .expect("Failed to get response body");
    assert!(
        text.contains(r#"<form method="post">
      <input type="text" name="name" placeholder="Name" aria-label="Name" required>
      <input type="url" name="redirect_uri" placeholder="Redirect URL" aria-label="Redirect URL" required>
      <label for="type">Client type</label>
      <select name="type" id="type" required>
        <option value="public" selected>Public</option>
        <option value="confidential">Confidential</option>
      </select>
      <button type="submit" class="contrast">Register client</button>
    </form>"#),
        "Response body contains client registration form"
    )
    
}

#[tokio::test]
pub async fn register_client_form_errors() {
    // Arrange
    let state = spawn_app().await;
    let client = state.api_client;
    let invalid_cases = [
        (
            serde_json::json!({
                "redirect_uri": "https://foo/authorized",
                "type": "confidential",
            }),
            "missing client name"
        ),
        (
            serde_json::json!({
                "name": "foo client",
                "type": "confidential",
            }),
            "missing redirect URI"
        ),
        (
            serde_json::json!({
                "name": "foo client",
                "redirect_uri": "https://foo/authorized",
                "type": "wrong_type",
            }),
            "wrong client type"
        ),
        (
            serde_json::json!({
                "name": "foo client",
                "redirect_uri": "https://foo/authorized",
            }),
            "missing client type"
        ),
        (
            serde_json::json!({}),
            "all fields missing"
        ),
    ];

    for (case, msg) in invalid_cases {
        // Act
        let response = client
            .post(&format!("{}/oauth/client", &state.app_address))
            .form(&case)
            .send()
            .await
            .expect("request to server api failed");

        // Assert
        assert_eq!(
            response.status().as_u16(),
            400,
            "{}: returns client error status", msg
        );
    }
}

#[tokio::test]
pub async fn happy_path_register_client_confidential() {
    // Arrange
    let state = spawn_app().await;
    let form = serde_json::json!({
        "name": "foo client",
        "redirect_uri": "https://foo/authorized",
        "type": "confidential",
    });
    state.signin("foo", "secret").await;

    // Act
    let response = state.api_client
        .post(&format!("{}/oauth/client", &state.app_address))
        .form(&form)
        .send()
        .await
        .expect("request to server api failed");

    // Assert
    assert_eq!(
        response.status().as_u16(),
        200,
        "client registration form processed successfully"
    );
    let res = response
        .json::<ClientResponse>()
        .await
        .expect("Failed to get response body");
    assert!(
        !res.client_id.is_empty(),
        "The client_id field of the response is NOT empty"
    );
    assert!(
        !res.client_secret.is_empty(),
        "The client_secret field of the response is NOT empty"
    );
     assert_eq!(
        res.client_secret.len(),
        32,
        "The client_secret field contains a response of the right length for nanoid output"
    );
   
}

#[tokio::test]
pub async fn happy_path_client_authorization_flow() {
    // Arrange
    let dummy_client = reqwest::Client::new();
    let state = spawn_app().await;
    let form = serde_json::json!({
        "name": "foo client",
        "redirect_uri": "http://localhost:3001/endpoint",
        "type": "confidential",
    });
    state.signin("foo", "secret").await;

    // Register Client
    // Act -1
    let response = state.api_client
        .post(&format!("{}/oauth/client", &state.app_address))
        .form(&form)
        .send()
        .await
        .expect("request to server api failed");

    // Assert -1
    assert_eq!(
        response.status().as_u16(),
        200,
        "client registration form processed successfully"
    );
    let res = response
        .json::<ClientResponse>()
        .await
        .expect("Failed to get response body");
    assert!(
        !res.client_id.is_empty(),
        "The client_id field of the response is NOT empty"
    );
    assert!(
        !res.client_secret.is_empty(),
        "The client_secret field of the response is NOT empty"
    );
     assert_eq!(
        res.client_secret.len(),
        32,
        "The client_secret field contains a response of the right length for nanoid output"
    );

    // Get Code
    // Arrange -2
    let code_verifier = pkce::code_verifier(128);
    let code_challenge = pkce::code_challenge(&code_verifier);
    let query = serde_json::json!({
        "response_type": "code",
        "redirect_uri": "http://localhost:3001/endpoint",
        "client_id": res.client_id,
        "scope": "account:read account:write",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": "12345",
    });

    // Act -2
    tracing::debug!("GET /oauth/authorize");
    tracing::debug!("Query: {:?}", query);
    let response = state.api_client
        .get(format!("{}/oauth/authorize", state.app_address))
        .basic_auth(res.client_id, Some(res.client_secret))
        .query(&query)
        .send()
        .await
        .expect("failed to get response from api client");
    assert_is_redirect_to(&response, "http://localhost:3000/consent", 302);
    let body = response
        .text()
        .await
        .expect("unable to decode response from dummy client");
    assert_eq!(
        body,
        "placeholder....",
        "placeholder"
    );
   
}
