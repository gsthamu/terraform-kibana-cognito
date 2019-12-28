# terraform-kibana-cognito
Create cognito enabled kibana by terraform

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
