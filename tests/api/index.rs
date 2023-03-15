use crate::helpers::spawn_app;

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
