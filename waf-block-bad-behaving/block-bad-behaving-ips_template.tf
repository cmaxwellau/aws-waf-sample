# maximum bad requests per minute per IP. Default: 50
variable "request_threshold" { default = "50" }

#duration (in seconds) the IP should be blocked for. Default: 4 hours (14400 sec)
variable "waf_block_period" { default = "14400" }

variable "aws_region" {default = "ap-southeast-1"}

provider "aws" {
  region = "${var.aws_region}"
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "ops_bucket" {
  bucket_prefix = "waf-block-ops"
  acl           = "private"
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "./parser.py"
  output_path = "parser.zip"
}

resource "aws_s3_bucket_object" "lambda_deployment" {
  depends_on  = ["aws_s3_bucket.ops_bucket" ]
  bucket      = "${aws_s3_bucket.ops_bucket.id}"
  key         = "${data.archive_file.lambda_zip.output_path}"
  source      = "${data.archive_file.lambda_zip.output_path}"
  etag        = "${data.archive_file.lambda_zip.output_md5}"
}

resource "aws_waf_ipset" "ipset_manual" {
  name = "Manual Block Set"
}

resource "aws_waf_rule" "rule_manual" {
  depends_on  = ["aws_waf_ipset.ipset_manual"]
  name        = "ManualBlockRule"
  metric_name = "ManualBlockRule"

  predicates {
    data_id = "${aws_waf_ipset.ipset_manual.id}"
    negated = false
    type    = "IPMatch"
  }
}

resource "aws_waf_ipset" "ipset_auto" {
  name = "auto Block Set"
}

resource "aws_waf_rule" "rule_auto" {
  depends_on  = ["aws_waf_ipset.ipset_auto"]
  name        = "AutoBlockRule"
  metric_name = "AutoBlockRule"

  predicates {
    data_id = "${aws_waf_ipset.ipset_auto.id}"
    negated = false
    type    = "IPMatch"
  }
}

resource "aws_waf_web_acl" "waf_acl" {
  depends_on  = ["aws_waf_rule.rule_auto", "aws_waf_rule.rule_manual"]
  name        = "Malicious Requesters"
  metric_name = "MaliciousRequesters"

  default_action {
    type = "ALLOW"
  }

  rules {
	    action {
	      type = "BLOCK"
	    }
	    priority = 1
	    rule_id  = "${aws_waf_rule.rule_manual.id}"
	  }
  rules
    {
	    action {
	      type = "BLOCK"
	    }
	    priority = 2
	    rule_id  = "${aws_waf_rule.rule_auto.id}"
	  }
  
}

resource "aws_iam_role" "lambda_role" {
  name_prefix        = "lambda_execution_role"  
  path               = "/"
  assume_role_policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "Service": ["lambda.amazonaws.com"]
      },
      "Action": ["sts:AssumeRole"]
    }]
}
POLICY
}



resource "aws_iam_role_policy" "lambda_role_policy" {
  role   = "${aws_iam_role.lambda_role.id}"
  depends_on = [
        "aws_waf_ipset.ipset_manual",
        "aws_waf_ipset.ipset_auto",
        "aws_waf_rule.rule_manual",
        "aws_waf_rule.rule_auto",
        "aws_waf_web_acl.waf_acl"
   ]
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "waf:*",
      "Resource": [
        "${aws_waf_ipset.ipset_manual.arn}",
        "${aws_waf_ipset.ipset_auto.arn}",
        "arn:aws:waf::${data.aws_caller_identity.current.account_id}:rules/${aws_waf_rule.rule_manual.id}",
        "arn:aws:waf::${data.aws_caller_identity.current.account_id}:rules/${aws_waf_rule.rule_auto.id}",
        "arn:aws:waf::${data.aws_caller_identity.current.account_id}:webacl/${aws_waf_web_acl.waf_acl.id}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "logs:*",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": [
        "${aws_s3_bucket.ops_bucket.arn}",
        "${aws_s3_bucket.ops_bucket.arn}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": [
        "${aws_s3_bucket.access_log_bucket.arn}",
        "${aws_s3_bucket.access_log_bucket.arn}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "cloudwatch:PutMetricData",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_lambda_function" "lambda_function" {
  depends_on  = ["aws_iam_role.lambda_role", "aws_s3_bucket_object.lambda_deployment"]
  function_name    = "block-bad-behiaving-ips"
  role             = "${aws_iam_role.lambda_role.arn}"
  handler          = "parser.lambda_handler"
  runtime          = "python2.7"
  memory_size      = "512"
  timeout          = "300"
  s3_bucket        = "${aws_s3_bucket.ops_bucket.id}"
  s3_key           = "${data.archive_file.lambda_zip.output_path}"
  description      = "${var.request_threshold}:${var.waf_block_period}"

  environment {
    variables = {
      OUTPUT_BUCKET = "${aws_s3_bucket.ops_bucket.id}"
      IP_SET_ID_MANUAL_BLOCK = "${aws_waf_ipset.ipset_manual.id}"
      IP_SET_ID_AUTO_BLOCK = "${aws_waf_ipset.ipset_auto.id}"
      BLACKLIST_BLOCK_PERIOD = "${var.waf_block_period}"
      REQUEST_PER_MINUTE_LIMIT = "${var.request_threshold}"
    }
  }  
}

resource "aws_lambda_permission" "allow_lambda_function" {
  action         = "lambda:InvokeFunction"
  function_name  = "${aws_lambda_function.lambda_function.arn}"
  principal      = "s3.amazonaws.com"
  source_account = "${data.aws_caller_identity.current.account_id}"
  source_arn     = "${aws_s3_bucket.access_log_bucket.arn}"
}


resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = "${aws_s3_bucket.access_log_bucket.id}"

  lambda_function {
    id = "logfile_created_notify_lambda"
    lambda_function_arn = "${aws_lambda_function.lambda_function.arn}"
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".gz"
  }
}


resource "aws_s3_bucket" "access_log_bucket" {
  bucket_prefix = "send-cloudfront-logs-here"  
  acl    = "private"
}
