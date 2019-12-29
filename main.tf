resource "aws_cognito_user_pool" "kibana_user_pool" {
  name = "kibana_user_pool"
}

resource "aws_cognito_user_pool_domain" "kibana-domain" {
  domain       = "kibana-cognito-example"
  user_pool_id = aws_cognito_user_pool.kibana_user_pool.id
}

resource "aws_cognito_identity_pool" "kibana_identity_pool" {
  identity_pool_name               = "kibana_identity_pool"
  allow_unauthenticated_identities = true
}
