resource "aws_cognito_user_pool" "kibana_user_pool" {
  name = "kibana_user_pool"
}

resource "aws_cognito_user_pool_domain" "kibana-domain" {
  domain       = var.user_pool_domain
  user_pool_id = aws_cognito_user_pool.kibana_user_pool.id
}

resource "aws_cognito_identity_pool" "kibana_identity_pool" {
  identity_pool_name               = "kibana_identity_pool"
  allow_unauthenticated_identities = true
}

resource "aws_iam_role" "kibana_cognito_authenticated" {
  name = "KibanaCognitoAuthenticated"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.kibana_identity_pool.id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "kibana_identity_authenticated" {
  name = "kibana_identity_authenticated_policy"
  role = aws_iam_role.kibana_cognito_authenticated.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "mobileanalytics:PutEvents",
        "cognito-sync:*",
        "cognito-identity:*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
EOF
}


resource "aws_iam_role" "kibana_cognito_unauthenticated" {
  name = "KibanaCognitoUnauthenticated"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.kibana_identity_pool.id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "unauthenticated"
        }
      }
    }
  ]
}
EOF
}


resource "aws_iam_role_policy" "kibana_identity_unauthenticated" {
  name = "kibana_identity_unauthenticated_policy"
  role = aws_iam_role.kibana_cognito_unauthenticated.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "mobileanalytics:PutEvents",
        "cognito-sync:*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
EOF
}

resource "aws_cognito_identity_pool_roles_attachment" "cognito_roles_attachment" {
  identity_pool_id = aws_cognito_identity_pool.kibana_identity_pool.id

  roles = {
    "authenticated"   = aws_iam_role.kibana_cognito_authenticated.arn
    "unauthenticated" = aws_iam_role.kibana_cognito_unauthenticated.arn
  }
}


data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
# data "aws_subnet_ids" "selected" {
#   vpc_id = var.vpc_id
# }
resource "aws_elasticsearch_domain" "elasticsearch_sample" {
  domain_name           = var.es_domain
  elasticsearch_version = "7.1"

  cluster_config {
    instance_type = "t2.small.elasticsearch"
  }

  snapshot_options {
    automated_snapshot_start_hour = 23
  }

  tags = {
    Domain = "TestDomain"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 20
  }

  vpc_options {
    subnet_ids = [var.subnet_id]
    security_group_ids = [var.security_group_id]
  }

  cognito_options {
    enabled          = true
    user_pool_id     = aws_cognito_user_pool.kibana_user_pool.id
    identity_pool_id = aws_cognito_identity_pool.kibana_identity_pool.id
    role_arn         = var.cognito_role_arn
  }

  access_policies = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "es:*",
      "Principal": "*",
      "Effect": "Allow",
      "Resource": "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.es_domain}/*"
    }
  ]
}
POLICY
}
