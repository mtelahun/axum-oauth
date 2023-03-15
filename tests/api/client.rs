use csrf::CsrfToken;
use serde::Serialize;

use crate::helpers::{spawn_app, ClientResponse, ClientType, Token};

#[derive(Debug, Serialize)]
struct AuthorizationQuery {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    response_type: String,
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
            422,
            "{}: returns client error status",
            msg
        );
    }
}

#[tokio::test]
pub async fn happy_path_register_client_confidential() {
    // Arrange
    let state = spawn_app().await;
    let params = serde_json::json!({
        "name": "foo client",
        "redirect_uri": "https://foo/authorized",
        "type": "confidential",
    });

    // Act
    let response = state
        .api_client
        .post(&format!("{}/oauth/client", &state.app_address))
        .form(&params)
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

    let client_secret = res
        .client_secret
        .clone()
        .map_or(String::new(), |secret| secret);

    assert!(
        !res.client_id.is_empty(),
        "The client_id field of the response is NOT empty"
    );
    assert!(
        !client_secret.is_empty(),
        "The client_secret field of the response is NOT empty"
    );
    assert_eq!(
        client_secret.len(),
        32,
        "The client_secret field contains a response of the right length for nanoid output"
    );
}

#[tokio::test]
pub async fn happy_path_register_client_public() {
    // Arrange
    let state = spawn_app().await;
    let form = serde_json::json!({
        "name": "foo client",
        "redirect_uri": "https://foo/authorized",
        "type": "public",
    });

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
    let client_secret = res
        .client_secret
        .clone()
        .map_or(String::new(), |secret| secret);
    assert!(
        !res.client_id.is_empty(),
        "The client_id field of the response is NOT empty"
    );
    assert!(
        client_secret.is_empty(),
        "The client_secret field of a public client IS empty"
    );
}

#[tokio::test]
pub async fn happy_path_confidential_client_authorization_flow() {
    // Arrange - 1
    let state = spawn_app().await;
    let params = serde_json::json!({
        "name": "foo client",
        "redirect_uri": "http://localhost:3001/endpoint",
        "type": "confidential",
    });
    state.signin("bob", "secret").await;
    let res = state
        .register_client(&params, ClientType::Confidential)
        .await;

    let code_verifier = pkce::code_verifier(128);
    let code_challenge = pkce::code_challenge(&code_verifier);
    let csrf_token = CsrfToken::new(nanoid::nanoid!().into_bytes()).b64_string();
    let query = serde_json::json!({
        "response_type": "code",
        "redirect_uri": "http://localhost:3001/endpoint",
        "client_id": res.client_id.clone(),
        "scope": "account:read account:write account:follow",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": csrf_token,
    });

    // Act - 1
    let body = state.get_consent_prompt_confidential(&query).await;
    let consent_response = state.owner_consent_allow(&body).await;
    let authorization_code = state
        .capture_authorizer_redirect(
            &res,
            &consent_response,
            ClientType::Confidential,
            &csrf_token,
        )
        .await;

    // Arrange - 2
    let cv = String::from_utf8_lossy(&code_verifier);
    let params = vec![
        ("grant_type", "authorization_code"),
        ("redirect_uri", "http://localhost:3001/endpoint"),
        ("code", &authorization_code),
        ("code_verifier", &cv),
    ];

    // Act - 2
    let token = state
        .exchange_auth_code_for_token(&res, ClientType::Confidential, &params)
        .await;

    // Act - 3
    let refresh_token = token.refresh_token.clone().unwrap();
    let params = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh_token),
        ("scope", "account:read account:write"),
    ];
    let refreshed_token = state
        .refresh_token(
            &res,
            ClientType::Confidential,
            &params,
            token.access_token.unwrap(),
        )
        .await;

    // Assert - 3
    let json_user = r#""login":"bob","name":"Robert","authorized_clients":"#;
    state
        .access_resource_success(&refreshed_token.access_token.unwrap(), json_user)
        .await;
}

#[tokio::test]
pub async fn happy_path_public_client_authorization_flow() {
    // Arrange - 1
    let state = spawn_app().await;
    let params = serde_json::json!({
        "name": "foo client",
        "redirect_uri": "http://localhost:3001/endpoint",
        "type": "public",
    });
    let res = state.register_client(&params, ClientType::Public).await;
    state.signin("bob", "secret").await;

    let code_verifier = pkce::code_verifier(128);
    let code_challenge = pkce::code_challenge(&code_verifier);
    let csrf_token = CsrfToken::new(nanoid::nanoid!().into_bytes()).b64_string();
    let query = serde_json::json!({
        "response_type": "code",
        "redirect_uri": "http://localhost:3001/endpoint",
        "client_id": res.client_id.clone(),
        "scope": "account:read account:write",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": csrf_token,
    });

    // Act - 1
    let body = state.get_consent_prompt_public(&&query).await;
    let consent_response = state.owner_consent_allow(&body).await;
    let authorization_code = state
        .capture_authorizer_redirect(&res, &consent_response, ClientType::Public, &csrf_token)
        .await;

    // Arrange - 2
    let cv = String::from_utf8_lossy(&code_verifier);
    let params = vec![
        ("grant_type", "authorization_code"),
        ("redirect_uri", "http://localhost:3001/endpoint"),
        ("code", &authorization_code),
        ("client_id", &res.client_id),
        ("code_verifier", &cv),
    ];

    // Act - 2
    let token = state
        .exchange_auth_code_for_token(&res, ClientType::Public, &params)
        .await;

    // Act - 3
    let refresh_token = token.refresh_token.clone().unwrap();
    let params = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh_token),
        ("scope", "account:read account:write"),
    ];
    let refreshed_token = state
        .refresh_token(
            &res,
            ClientType::Public,
            &params,
            token.access_token.unwrap(),
        )
        .await;

    // Assert - 3
    let json_user = r#""login":"bob","name":"Robert","authorized_clients":"#;
    state
        .access_resource_success(&refreshed_token.access_token.unwrap(), json_user)
        .await;
}

#[tokio::test]
#[ignore]
pub async fn happy_path_client_credentials_authorization_flow() {
    // Arrange 1
    let state = spawn_app().await;
    let params = serde_json::json!({
        "name": "foo service client",
        "redirect_uri": "http://localhost:3001/endpoint",
        "type": "confidential",
    });
    state.signin("bob", "secret").await;
    let res = state
        .register_client(&params, ClientType::Confidential)
        .await;

    let params = vec![
        ("grant_type", "client_credentials"),
        ("scope", "account:read account:write"),
    ];

    // Act 1
    // let token = state.exchange_auth_code_for_token(&res, ClientType::Confidential, &params).await;
    let response = state
        .api_client
        .post(format!("{}/oauth/token", state.app_address))
        .basic_auth(
            res.client_id.clone(),
            Some(res.client_secret.clone().unwrap()),
        )
        .form(&params)
        .send()
        .await
        .expect("failed to get response from api client");

    // Assert 1
    let code = response.status().as_u16();
    let token = response.text().await.expect("failed to get response body");
    tracing::debug!("Token Response: {:?}", token);
    assert_eq!(code, 200, "Request for access token returns successfully");
    let token: Token = serde_json::from_str(token.as_str()).unwrap();
    assert_eq!(token.token_type, "bearer", "Token is a Bearer token");
    for s in ["account:read", "account:write"] {
        assert!(token.scope.contains(s), "Token scope includes {}", s);
    }
    assert!(
        !token.access_token.is_none(),
        "Access token contains a value"
    );
    assert!(
        token.error.is_none(),
        "Error value of token response is empty"
    );

    // Assert 2
    state
        .access_resource_success(&token.access_token.unwrap(), res.client_id.clone().as_str())
        .await;
}
