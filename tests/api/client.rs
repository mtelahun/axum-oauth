use serde::Deserialize;

use crate::helpers::spawn_app;


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

#[derive(Deserialize)]
struct ClientResponse {
    client_id: String,
    client_secret: String,
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
