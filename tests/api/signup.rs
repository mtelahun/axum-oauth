use crate::helpers::spawn_app;

#[tokio::test]
async fn signup_form_fields_problem() {
    // Arrange
    let test_state = spawn_app().await;
    let client = test_state.api_client;
    let invalid_cases = [
        (
            serde_json::json!({
                "password": "secret",
            }),
            "password only",
        ),
        (
            serde_json::json!({
                "username": "bob",
            }),
            "username only",
        ),
        (
            serde_json::json!({
                "given_name": "Robert",
            }),
            "given name only",
        ),
        (
            serde_json::json!({
                "username": "bob",
                "given_name": "Robert",
            }),
            "no password",
        ),
        (
            serde_json::json!({
                "password": "secret",
                "given_name": "Robert",
            }),
            "no username",
        ),
        (serde_json::json!({}), "empty form"),
    ];

    for (case, msg) in invalid_cases {
        // Act
        let response = client
            .post(&format!("{}/oauth/signup", &test_state.app_address))
            .form(&case)
            .send()
            .await
            .expect("request to server api failed");

        // Assert
        assert_eq!(
            response.status().as_u16(),
            422,
            "{} returns client error status",
            msg
        );
    }
}

#[tokio::test]
async fn signup_existing_user() {
    // Arrange
    let test_state = spawn_app().await;
    let client = test_state.api_client;
    let form = serde_json::json!({
        "username": "bob",
        "password": "secret",
        "given_name": "Robert",
    });

    // Act
    let response = client
        .post(&format!("{}/oauth/signup", &test_state.app_address))
        .form(&form)
        .send()
        .await
        .expect("request to server api failed");

    // Assert
    assert_eq!(
        response.status().as_u16(),
        409,
        "signup existing user returns 409 Conflict",
    );
}

#[tokio::test]
async fn happy_path_signup_form() {
    // Arrange
    let test_state = spawn_app().await;
    let client = test_state.api_client;
    let form = serde_json::json!({
        "username": "alice",
        "password": "secret",
        "given_name": "Alice",
    });

    // Act
    let response = client
        .post(&format!("{}/oauth/signup", &test_state.app_address))
        .form(&form)
        .send()
        .await
        .expect("request to server api failed");

    // Assert
    assert_eq!(
        response.status().as_u16(),
        201,
        "successful signup returns 201 Created",
    );
}
