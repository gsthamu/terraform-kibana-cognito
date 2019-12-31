variable "user_pool_domain" {
  description = "User pool domain prefix"
}

variable "cognito_role_arn" {
  description = "IAM role attached AmazonESCognitoAccess"
}

variable "es_domain" {
  description = "elasticsearch domain"
}

variable "source_ip" {
  description = "IP address to access to elasticsearch"
}
