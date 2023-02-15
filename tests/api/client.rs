use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::helpers::{assert_is_redirect_to, spawn_app, Token};

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
    let text = response.text().await.expect("Failed to get response body");
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
            "missing client name",
        ),
        (
            serde_json::json!({
                "name": "foo client",
                "type": "confidential",
            }),
            "missing redirect URI",
        ),
        (
            serde_json::json!({
                "name": "foo client",
                "redirect_uri": "https://foo/authorized",
                "type": "wrong_type",
            }),
            "wrong client type",
        ),
        (
            serde_json::json!({
                "name": "foo client",
                "redirect_uri": "https://foo/authorized",
            }),
            "missing client type",
        ),
        (serde_json::json!({}), "all fields missing"),
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
            "{}: returns client error status",
            msg
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
    let response = state
        .api_client
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
    let state = spawn_app().await;
    let form = serde_json::json!({
        "name": "foo client",
        "redirect_uri": "http://localhost:3001/endpoint",
        "type": "confidential",
    });
    state.signin("foo", "secret").await;

    // Register Client
    // Act -1
    let response = state
        .api_client
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

    // Ask owner consent
    // Arrange -2
    let code_verifier = pkce::code_verifier(128);
    let code_challenge = pkce::code_challenge(&code_verifier);
    let query = serde_json::json!({
        "response_type": "code",
        "redirect_uri": "http://localhost:3001/endpoint",
        "client_id": res.client_id.clone(),
        "scope": "account:read account:write account:follow",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": "12345",
    });

    // Act -2
    tracing::debug!("Test::GET /oauth/authorize?{:?}", query);
    let response = state
        .api_client
        .get(format!("{}/oauth/authorize", state.app_address))
        .basic_auth(res.client_id.clone(), Some(res.client_secret.clone()))
        .query(&query)
        .send()
        .await
        .expect("failed to get response from api client");

    // Assert -2
    assert_eq!(
        response.status().as_u16(),
        200,
        "The authorization endpoint returns successfully"
    );
    let body = response
        .text()
        .await
        .expect("unable to decode response from dummy client");
    tracing::debug!("consent page:\n{}", body);
    assert!(
        body.contains("<h1>Authorize foo client</h1>"),
        "The authorization endpoint returned a consent page that shows the client name"
    );
    assert!(
        body.contains("<h4>foo client wants access to your <em>foo</em> account"),
        "The authorization endpoint returned a consent page that shows the target resource"
    );
    assert!(
        body.contains("account:read"),
        "The authorization endpoint returned a consent page that shows the requested (read) permissions"
    );
    assert!(
        body.contains("account:write"),
        "The authorization endpoint returned a consent page that shows the requested (write) permissions"
    );
    assert!(
        body.contains("account:follow"),
        "The authorization endpoint returned a consent page that shows the requested (follow) permissions"
    );

    // Owner gives consent
    // Arrange -3
    let re_action = Regex::new("formaction=\"(.*)\"").unwrap();
    let caps = re_action.captures(&body).unwrap();
    let allow_path = caps.get(1).map_or("/", |m| m.as_str());

    let allow_path = urlencoding::decode(allow_path).expect("failed to decode formaction");
    let allow_path = html_escape::decode_html_entities(&allow_path);
    tracing::debug!("RE path: {}", allow_path);

    // Act -3
    tracing::debug!(
        "uri: {}",
        format!("{}/oauth/{}", state.app_address, allow_path)
    );
    let response = state
        .api_client
        .post(format!("{}/oauth/{}", state.app_address, allow_path))
        .basic_auth(res.client_id.clone(), Some(res.client_secret.clone()))
        .send()
        .await
        .expect("failed to get response from api client");

    // Assert -3
    assert_is_redirect_to(&response, 302, "http://localhost:3001/endpoint?code=", true);

    // Get access token
    // Arrange -4
    let location = response
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .expect("failed to get redirect location");
    tracing::debug!("Client redirect: {}", location);
    let re_code = Regex::new("\\?code=(.*)\\&").unwrap();
    let caps = re_code.captures(&location).unwrap();
    let code = caps.get(1).map_or("X", |m| m.as_str());
    let code = urlencoding::decode(code).expect("failed to decode authorization code");
    tracing::debug!("Extracted code: {}", code);

    let cv = String::from_utf8_lossy(&code_verifier);
    let params = vec![
        ("grant_type", "authorization_code"),
        ("redirect_uri", "http://localhost:3001/endpoint"),
        ("code", &code),
        ("code_verifier", &cv),
    ];

    // Act -4
    let response = state
        .api_client
        .post(format!("{}/oauth/token", state.app_address))
        .basic_auth(res.client_id.clone(), Some(res.client_secret.clone()))
        .form(&params)
        .send()
        .await
        .expect("failed to get response from api client");

    // Assert -4
    assert_eq!(
        response.status().as_u16(),
        200,
        "Request for access token returns successfully"
    );
    let token = response.text().await.expect("failed to get response body");
    tracing::debug!("Token Response: {:?}", token);
    let token: Token = serde_json::from_str(token.as_str()).unwrap();
    tracing::debug!("Token Serialized: {:?}", token);
    assert_eq!(token.token_type, "bearer", "Token is a Bearer token");
    for s in ["account:read", "account:write", "account:follow"] {
        assert!(token.scope.contains(s), "Token scope includes {}", s);
    }
    assert!(
        !token.access_token.is_none(),
        "Access token contains a value"
    );
    assert!(
        !token.refresh_token.is_none(),
        "Refresh token contains a value"
    );
    assert!(
        token.error.is_none(),
        "Error value of token response is empty"
    );

    // Refresh the token
    // Arrange -5
    let old_token = token.access_token.clone().unwrap();
    let refresh_token = token.refresh_token.clone().unwrap();
    let params = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh_token),
        ("scope", "account:read account:write account:follow"),
    ];

    // Act -5
    let response = state
        .api_client
        .post(format!("{}/oauth/token", state.app_address))
        .basic_auth(res.client_id.clone(), Some(res.client_secret.clone()))
        .form(&params)
        .send()
        .await
        .expect("failed to get response from api client");

    // Assert -5
    assert_eq!(
        response.status().as_u16(),
        200,
        "Request for access token returns successfully"
    );
    let token = response.text().await.expect("failed to get response body");
    tracing::debug!("Token Response: {:?}", token);
    let token: Token = serde_json::from_str(token.as_str()).unwrap();
    tracing::debug!("Token Serialized: {:?}", token);
    assert_eq!(token.token_type, "bearer", "Token is a Bearer token");
    for s in ["account:read", "account:write", "account:follow"] {
        assert!(token.scope.contains(s), "Token scope includes {}", s);
    }
    let new_token = token.access_token.clone().unwrap();
    assert!(
        !token.access_token.is_none() && new_token != old_token,
        "New access token is different from the previous token"
    );
    assert!(
        !token.refresh_token.is_none(),
        "Refresh token contains a value"
    );
    assert!(
        token.error.is_none(),
        "Error value of token response is empty"
    );

    // Use the access token
    // Arrange - 6
    let token = new_token;

    // Act - 6
    let response = state
        .api_client
        .get(&format!("{}/oauth/whoami", &state.app_address))
        .bearer_auth(token)
        .send()
        .await
        .expect("request to client api failed");

    // Assert - 6
    assert_eq!(
        response.status().as_u16(),
        200,
        "Access to protected resource succeeded"
    );
    let body = response.text().await.unwrap();
    assert!(
        body.contains(":foo"),
        "Confirm access to protected resource"
    );
}
