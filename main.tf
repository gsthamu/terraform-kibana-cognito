resource "aws_cognito_user_pool" "kibana_user_pool" {
  name = "kibana_user_pool"
}

resource "aws_cognito_user_pool_domain" "kibana-domain" {
  domain       = "kibana-domain-sample"
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

resource "aws_elasticsearch_domain" "elasticsearch_sample" {
  domain_name           = "cognito-test"
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

  cognito_options {
    enabled          = true
    user_pool_id     = aws_cognito_user_pool.kibana_user_pool.id
    identity_pool_id = aws_cognito_identity_pool.kibana_identity_pool.id
    role_arn         = "arn:aws:iam::980831117329:role/service-role/CognitoAccessForAmazonES"
  }
}
