use crate::helpers::{spawn_app, assert_is_redirect_to};

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
            "no username"
        ),
        (
            serde_json::json!({
                "username": "foo",
            }),
            "no password"
        ),
        (
            serde_json::json!({}),
            "empty form"
        ),
    ];

    for (case, msg) in invalid_cases {
        // Act
        let response = client
            .post(&format!("{}/oauth/signin", &test_state.app_address))
            .form(&case)
            .send()
            .await
            .expect("request to server api failed");

        // Assert
        assert_eq!(
            response.status().as_u16(),
            400,
            "{} returns client error status", msg
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
            "invalid username"
        ),
        (
            serde_json::json!({
                "username": "foo",
                "password": "not_my_secret"
            }),
            "invalid password"
        ),
    ];

    for (case, msg) in invalid_cases {
        // Act
        let response = client
            .post(&format!("{}/oauth/signin", &test_state.app_address))
            .form(&case)
            .send()
            .await
            .expect("request to server api failed");

        // Assert
        println!("response: {:?}", response);
        assert_eq!(
            response.status().as_u16(),
            401,
            "{} returns client error 401 Unauthorized", msg
        );
    }
}

#[tokio::test]
async fn happy_path_signin_form() {
    // Arrange
    let test_state = spawn_app().await;
    let client = test_state.api_client;
    let form = serde_json::json!({
        "username": "foo",
        "password": "secret",
    });

    // Act
    let response = client
        .post(&format!("{}/oauth/signin", &test_state.app_address))
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
    assert_is_redirect_to(&response, "/oauth/", 303);
}
