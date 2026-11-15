use crate::helpers::{assert_is_redirect_to, spawn_app};

#[tokio::test]
async fn signin_form_fields_problem() {
    // Arrange
    let test_state = spawn_app().await;
    let client = test_state.api_client;
    let invalid_cases = [
        (
            serde_json::json!({
                "password": "secret",
            }),
            "no username",
        ),
        (
            serde_json::json!({
                "username": "bob",
            }),
            "no password",
        ),
        (serde_json::json!({}), "empty form"),
    ];

    for (case, msg) in invalid_cases {
        // Act
        let response = client
            .post(format!("{}/oauth/signin", test_state.app_address))
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
async fn signin_form_wrong_credentials() {
    // Arrange
    let test_state = spawn_app().await;
    let client = test_state.api_client;
    let invalid_cases = [
        (
            serde_json::json!({
                "username": "bar",
                "password": "secret",
            }),
            "invalid username",
        ),
        (
            serde_json::json!({
                "username": "bob",
                "password": "not_my_secret"
            }),
            "invalid password",
        ),
    ];

    for (case, msg) in invalid_cases {
        // Act
        let response = client
            .post(format!("{}/oauth/signin", test_state.app_address))
            .form(&case)
            .send()
            .await
            .expect("request to server api failed");

        // Assert
        println!("response: {:?}", response);
        assert_eq!(
            response.status().as_u16(),
            401,
            "{} returns client error 401 Unauthorized",
            msg
        );
    }
}

#[tokio::test]
async fn happy_path_signin_form() {
    // Arrange
    let test_state = spawn_app().await;
    let client = test_state.api_client;
    let form = serde_json::json!({
        "username": "bob",
        "password": "secret",
    });

    // Act
    let response = client
        .post(format!("{}/oauth/signin", test_state.app_address))
        .form(&form)
        .send()
        .await
        .expect("request to server api failed");

    // Assert
    assert_eq!(
        response.status().as_u16(),
        303,
        "correct credentials result in 303 redirect to oauth root uri",
    );
    assert_is_redirect_to(&response, 303, "/oauth/", false);
}

#[tokio::test]
async fn signin_ignores_offsite_callback() {
    // Arrange
    let test_state = spawn_app().await;
    let form = serde_json::json!({
        "username": "bob",
        "password": "secret",
    });
    let cases = [
        ("https://evil.example/", "/oauth/"),
        ("//evil.example/", "/oauth/"),
        ("/\\evil.example/", "/oauth/"),
        ("javascript:alert(1)", "/oauth/"),
        ("authorize?client_id=foo", "authorize?client_id=foo"),
    ];

    for (callback, expected) in cases {
        // Act
        let response = test_state
            .api_client
            .post(format!("{}/oauth/signin", test_state.app_address))
            .query(&[("callback", callback)])
            .form(&form)
            .send()
            .await
            .expect("request to server api failed");

        // Assert
        assert_is_redirect_to(&response, 303, expected, false);
    }
}

#[tokio::test]
async fn wrong_password_does_not_create_session() {
    // Arrange
    let test_state = spawn_app().await;
    let client = &test_state.api_client;
    let form = serde_json::json!({
        "username": "bob",
        "password": "not_my_secret",
    });
    let response = client
        .post(format!("{}/oauth/signin", test_state.app_address))
        .form(&form)
        .send()
        .await
        .expect("request to server api failed");
    assert_eq!(response.status().as_u16(), 401);

    // Act
    let response = client
        .get(format!("{}/oauth/authorize", test_state.app_address))
        .send()
        .await
        .expect("request to server api failed");

    // Assert
    assert_is_redirect_to(&response, 303, "/oauth/signin?", true);
}
