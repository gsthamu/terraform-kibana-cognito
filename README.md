# terraform-kibana-cognito
Create cognito enabled kibana by terraform

# Terraform
This repository uses following resources.

- [aws_elasticsearch_domain](https://www.terraform.io/docs/providers/aws/r/elasticsearch_domain.html)
- [aws_cognito_user_pool](https://www.terraform.io/docs/providers/aws/r/cognito_user_pool.html)
- [aws_cognito_user_pool_domain](https://www.terraform.io/docs/providers/aws/r/cognito_user_pool_domain.html)
- [aws_cognito_identity_pool](https://www.terraform.io/docs/providers/aws/r/cognito_identity_pool.html)
- [aws_iam_role](https://www.terraform.io/docs/providers/aws/r/iam_role.html)

# Quick Start

## Set Up
Copy `.env.sample` to `.env` and edit `.env` to add aws profile used in terraform.

```bash
cp .env.sample .env
```

Initialize terraform.

```bash
export $(cat .env | xargs) terraform init
```

## Run

Apply terraform

```bash
export $(cat .env | xargs) terraform apply
```
