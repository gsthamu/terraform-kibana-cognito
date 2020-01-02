# Cognito
# TODO: Create group which is allowed to use "es:ESHttp*".
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

data "aws_iam_policy_document" "cognito_authenticated_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type = "Federated"
      identifiers = ["cognito-identity.amazonaws.com"]
    }

    condition {
      test = "StringEquals"
      variable = "cognito-identity.amazonaws.com:aud"
      values = ["${aws_cognito_identity_pool.kibana_identity_pool.id}"]
    }

    condition {
      test = "ForAnyValue:StringLike"
      variable = "cognito-identity.amazonaws.com:amr"
      values = ["authenticated"]
    }
  }
}

resource "aws_iam_role" "kibana_cognito_authenticated" {
  name = "KibanaCognitoAuthenticated"

  assume_role_policy = data.aws_iam_policy_document.cognito_authenticated_assume_role_policy.json
}

data "aws_iam_policy_document" "identity_authenticated_assume_role_policy" {
  statement {
    actions = [
      "mobileanalytics:PutEvents",
      "cognito-sync:*",
      "cognito-identity:*"
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "kibana_identity_authenticated" {
  name = "kibana_identity_authenticated_policy"
  role = aws_iam_role.kibana_cognito_authenticated.id

  policy = data.aws_iam_policy_document.identity_authenticated_assume_role_policy.json
}

data "aws_iam_policy_document" "cognito_unauthenticated_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type = "Federated"
      identifiers = ["cognito-identity.amazonaws.com"]
    }

    condition {
      test = "StringEquals"
      variable = "cognito-identity.amazonaws.com:aud"
      values = ["${aws_cognito_identity_pool.kibana_identity_pool.id}"]
    }

    condition {
      test = "ForAnyValue:StringLike"
      variable = "cognito-identity.amazonaws.com:amr"
      values = ["unauthenticated"]
    }
  }
}

resource "aws_iam_role" "kibana_cognito_unauthenticated" {
  name = "KibanaCognitoUnauthenticated"

  assume_role_policy = data.aws_iam_policy_document.cognito_unauthenticated_assume_role_policy.json
}

data "aws_iam_policy_document" "identity_unauthenticated_assume_role_policy" {
  statement {
    actions = [
      "mobileanalytics:PutEvents",
      "cognito-sync:*",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "kibana_identity_unauthenticated" {
  name = "kibana_identity_unauthenticated_policy"
  role = aws_iam_role.kibana_cognito_unauthenticated.id

  policy = data.aws_iam_policy_document.identity_unauthenticated_assume_role_policy.json
}

resource "aws_cognito_identity_pool_roles_attachment" "cognito_roles_attachment" {
  identity_pool_id = aws_cognito_identity_pool.kibana_identity_pool.id

  roles = {
    "authenticated"   = aws_iam_role.kibana_cognito_authenticated.arn
    "unauthenticated" = aws_iam_role.kibana_cognito_unauthenticated.arn
  }
}

# Elasticsearch
data "aws_iam_policy_document" "es_cognito_assume_role_policy" {
  statement {
    principals {
      type = "Service"
      identifiers = ["es.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "es_cognito_access_role" {
  name               = "EsCognitoAccessRole"
  assume_role_policy = data.aws_iam_policy_document.es_cognito_assume_role_policy.json
}

resource "aws_iam_policy_attachment" "es_cognito_access_attach" {
  name       = "es_cognito_access_attach"
  roles      = [aws_iam_role.es_cognito_access_role.name]
  policy_arn = "arn:aws:iam::aws:policy/AmazonESCognitoAccess"
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_iam_policy_document" "es_access_policy" {
  statement {
    principals {
      type = "AWS"
      identifiers = ["arn:aws:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${aws_iam_role.es_cognito_access_role.name}/CognitoIdentityCredentials"]
    }

    actions = ["es:*"]

    resources = ["arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.es_domain}/*"]
  }
}

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
    subnet_ids         = [var.subnet_id]
    security_group_ids = [var.security_group_id]
  }

  cognito_options {
    enabled          = true
    user_pool_id     = aws_cognito_user_pool.kibana_user_pool.id
    identity_pool_id = aws_cognito_identity_pool.kibana_identity_pool.id
    role_arn         = aws_iam_role.es_cognito_access_role.arn
  }

  access_policies = data.aws_iam_policy_document.es_access_policy.json

  depends_on = [aws_iam_policy_attachment.es_cognito_access_attach]
}
