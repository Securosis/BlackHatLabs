# This workflow creates a CloudWatch alarm that sends email to the designated address if there are any changes to an IAM policy
# It's pretty static at this point, but easy to modify for other alarm needs.
# It is designed for a single region, and doesn't have a lot of pretty stuff you would want if using in production
# **WARNING WARNING WARNING** This also does *not* check to see if CloudTrail (and all the other pieces) already exist. It builds it from scratch and WILL cause errors if you run it in a region that is already configured for CloudTrail
# Copyright Securosis, LLC 2015 

require "rubygems"
# require 'bundler/setup'
require "aws-sdk"
require "json"
# require "pry"

class CloudTrailAlarm
  def initialize
    
    # Load configuration and credentials from a JSON file. Right now hardcoded to config.json in the app drectory.
    # TODO update to pull credentials from Trinity DB
    # TODO update to be able to handle multiple accounts and regions
    
    # Load from config file in same directory as code
    # In the future, we will need to adjust this to rotate through all accounts and regions for the user. AssumeRole should help.
    # config = JSON.load(File.read('config.json'))
    $region = "us-east-1"
    #  credentials... using hard coded for this PoC, but really should be an assumerole in the future.
    
    # creds = Aws::Credentials.new("#{config["aws"]["AccessKey"]}", "#{config["aws"]["SecretKey"]}")
    # Create clients for the various services we need. Loading them all here and setting them as Class variables.
    @ec2 = Aws::EC2::Client.new(region: "#{$region}")
    # hard code s3 to us standard region or some calls will later fail
    @s3 = Aws::S3::Client.new(region: "us-east-1")
    @iam = Aws::IAM::Client.new(region: $region)
    @sns = Aws::SNS::Client.new(region: $region)
    @cloudwatchlogs = Aws::CloudWatchLogs::Client.new(region: $region)
    @cloudwatch = Aws::CloudWatch::Client.new(region: $region)
    @cloudtrail = Aws::CloudTrail::Client.new(region: $region)

    # generate an 8 character random string to make carious names unique
    @random = rand(36**8).to_s(36)
  end
  
  def disable_cloudtrail
    # DO NOT RUN THIS IN PRODUCTION!!! It will delete the trail for the current region, and is only for lab purposes
    list = @cloudtrail.describe_trails()
    trail = list.trail_list.first.name
    @cloudtrail.delete_trail(name: trail)
    puts "Trail #{trail} deleted"
  end

  def create_private_s3_bucket(bucket_name)
    # add the string to the end of the requested name
    bucket_name = bucket_name + "-" + @random
    bucket = @s3.create_bucket(
      acl: "private",
      bucket: bucket_name
    )
    puts "created bucket #{bucket_name}"
    return bucket_name
  end
  
  def get_account_id()
    # pull creds for the account, the account ID will be in the result
    roles = @iam.get_account_authorization_details(filter: ["Role"])
    # parse out the account ID
    account_id = /(?<=arn:aws:iam::)(.{1,12})/.match(roles.role_detail_list.first.arn)
    puts "The account ID for the current credentials is #{account_id}"
    return account_id
  end
  
  def set_cloudtrail_s3_iam_policy(account_id, bucket_name)

    # create the json policy, substituting in the account ID and bucket name
    policy = %Q<{
            "Version": "2012-10-17",
            "Statement": [
              {
                "Sid": "AWSCloudTrailAclCheck20131101",
                "Effect": "Allow",
                "Principal": {
                  "AWS": [
                    "arn:aws:iam::903692715234:root",
                    "arn:aws:iam::859597730677:root",
                    "arn:aws:iam::814480443879:root",
                    "arn:aws:iam::216624486486:root",
                    "arn:aws:iam::086441151436:root",
                    "arn:aws:iam::388731089494:root",
                    "arn:aws:iam::284668455005:root",
                    "arn:aws:iam::113285607260:root",
                    "arn:aws:iam::035351147821:root"
                  ]
                },
                "Action": "s3:GetBucketAcl",
                "Resource": "arn:aws:s3:::#{bucket_name}"
              },
              {
                "Sid": "AWSCloudTrailWrite20131101",
                "Effect": "Allow",
                "Principal": {
                  "AWS": [
                    "arn:aws:iam::903692715234:root",
                    "arn:aws:iam::859597730677:root",
                    "arn:aws:iam::814480443879:root",
                    "arn:aws:iam::216624486486:root",
                    "arn:aws:iam::086441151436:root",
                    "arn:aws:iam::388731089494:root",
                    "arn:aws:iam::284668455005:root",
                    "arn:aws:iam::113285607260:root",
                    "arn:aws:iam::035351147821:root"
                  ]
                },
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::#{bucket_name}/AWSLogs/#{account_id}/*",
                "Condition": { 
                  "StringEquals": { 
                    "s3:x-amz-acl": "bucket-owner-full-control" 
                  }
                }
              }
            ]
          }  >

    # replace the existing bucket policy with the new one since it's a new bucket
    @s3.put_bucket_policy(
          bucket: bucket_name,
          policy: policy,
        )
    puts "Amazon S3 bucket policy for CloudTrail applied to bucket #{bucket_name}"
  end

  def create_cloudtrail_cloudwatch_log(account_id)
    # This creates a single cloudwatch log group 
    @cloudwatchlogs.create_log_group(
          log_group_name: "CloudTrail_#{@random}/logs",
        )
    # pull the ARN
    log_group = @cloudwatchlogs.describe_log_groups(log_group_name_prefix: "CloudTrail_#{@random}/logs")
    log_group = log_group.log_groups.first.arn
    puts "Cloudwatch log group CloudTrail_#{@random}/logs created"

    # start by creating the assume role policy, which is needed to tell AWS who is allowed to use the role. Had to go to support to figure that one out.

    assume_role_policy = %Q<{
                 "Version": "2012-10-17",
                 "Statement": [
                     {
                         "Sid": "",
                         "Effect": "Allow",
                         "Principal": {
                             "Service": "cloudtrail.amazonaws.com"
                         },
                         "Action": "sts:AssumeRole"
                     }
                 ]
              }>

    # build the policy needed for the IAM role
    role_policy = %Q<{
            "Version": "2012-10-17",
            "Statement": [
              {

                "Sid": "AWSCloudTrailCreateLogStream2014110",
                "Effect": "Allow",
                "Action": [
                  "logs:CreateLogStream"
                ],
                "Resource": [
                  "arn:aws:logs:#{$region}:#{account_id}:log-group:CloudTrail_#{@random}/logs:log-stream:#{account_id}_CloudTrail_#{@random}_#{$region}*"
                ]

              },
              {
                "Sid": "AWSCloudTrailPutLogEvents20141101",
                "Effect": "Allow",
                "Action": [
                  "logs:PutLogEvents"
                ],
                "Resource": [
                  "arn:aws:logs:#{$region}:#{account_id}:log-group:CloudTrail_#{@random}/logs:log-stream:#{account_id}_CloudTrail_#{@random}_#{$region}*"
                ]
              }
            ]
          }>
    # create the required IAM role and set the assume role policy
    role = @iam.create_role(
            role_name: "DELETE_CloudTrail_CloudWatchLogs_Role",
            assume_role_policy_document: assume_role_policy,
          )
    cloudwatch_log_hash = {}
    cloudwatch_log_hash = {:log_group_arn => log_group, :role_arn => role.role.arn}

    # now set the role policy to allow cloudtrail access
    @iam.put_role_policy(
            # required
            role_name: "DELETE_CloudTrail_CloudWatchLogs_Role",
            # required
            policy_name: "AllowCloudTrailCloudwatchAccess",
            # required
            policy_document: role_policy,
          )
    puts "IAM role CloudTrail_CloudWatchLogs_Role_#{@random} created for CloudTrail to post the logs."
    return cloudwatch_log_hash
  end

  def create_cloudtrail(bucket_name, cloudwatch_log_hash, account_id)
    # Wait 10 seconds for the IAM policy to propagate
    sleep 10
    # create a cloudtrail with the name of the region and the account ID and our random value
    name = "#{$region}-#{account_id}-#{@random}"
    trail = @cloudtrail.create_trail(
              name: name,
              s3_bucket_name: bucket_name,
              include_global_service_events: true,
              cloud_watch_logs_log_group_arn: cloudwatch_log_hash[:log_group_arn],
              cloud_watch_logs_role_arn: cloudwatch_log_hash[:role_arn],
            )
    puts "CloudTrail #{name} created."
    # wait a few seconds, then start logging
    sleep 5
    @cloudtrail.start_logging(
              name: name,
            )
    puts "CloudTrail logging enabled."
    sleep 5
  end

  def create_cloudwatch_alarm_topic(email)
    # This creates a new topic and sets the subscription to the provided email address
    # you could easily convert it to send to SMS, SQS, http, or another destination
    topic = @sns.create_topic(
                name: "cloudtrail_#{@random}",
              )
    puts "SNS topic cloudtrail_#{@random} created to send notifications."
    @sns.subscribe(
              topic_arn: topic.topic_arn,
              protocol: "email",
              endpoint: email,
            )
    # Check to make sure the user set up their email correctly to receive the messages
    puts "Please check your email to confirm the subscription, then hit Enter"
    blah = gets.chomp()
    puts "Sending test message. Please check your email, and hit enter when you receive it"
    # Send a test message
    @sns.publish(
              topic_arn: topic.topic_arn,
              message: "If you can read this, your CloudTrail alarm is set to receive messages.",
              subject: "CloudTrail Subscription Test",
            )
    blah = gets.chomp()
    return topic.topic_arn
  end

  def create_cloudwatch_cloudtrail_filter(filter, filter_name)
    # Creates the filter we will use to alarm on. The name is currently hard coded for CloudTrail.
    @cloudwatchlogs.put_metric_filter(
                      # required
                      log_group_name: "CloudTrail_#{@random}/logs",
                      # required
                      filter_name: filter_name,
                      # required
                      filter_pattern: filter,
                      # required
                      metric_transformations: [
                        {
                          # required
                          metric_name: filter_name,
                          # required
                          metric_namespace: "CloudTrailMetrics_#{@random}",
                          # required
                          metric_value: "1",
                        },
                      ],
                    )
  end

  def create_cloudwatch_cloudtrail_alarm(filter_name, topic_arn)
    # Creates the alarm based on the cloudwatch filter. some values currently hardcoded that might be better as variables later.
    @cloudwatch.put_metric_alarm(
                # required
                alarm_name: filter_name,
                alarm_description: "An alarm set for the #{filter_name} CloudTrail filter",
                actions_enabled: true,
                alarm_actions: ["#{topic_arn}"],
                # required
                metric_name: filter_name,
                # required
                namespace: "CloudTrailMetrics_#{@random}",
                # required
                statistic: "Sum",
                # required
                period: 60,
                # required
                evaluation_periods: 1,
                # required
                threshold: 1,
                # required
                comparison_operator: "GreaterThanOrEqualToThreshold",
              )
    puts "CloudWatch alarm for puts CloudWatch Logs filter #{filter_name}_#{@random} created."
  end

end

menuselect = 0
until menuselect == 7 do
    puts "\e[H\e[2J"
    puts "Welcome to AlarmSquirrel. This application creates a CloudWatch Alarm for any IAM metrics."
    puts ""
    puts "1. Run the workflow"
    puts "5. Delete your existing trail"
    puts "7. Exit"
    print "Select: "
    menuselect = gets.chomp
    if menuselect == "1"
      cloudtrail = CloudTrailAlarm.new()
      # create a cloudtrail bucket. 
      bucket_name = cloudtrail.create_private_s3_bucket("deletecloudtrail")
      account_id = cloudtrail.get_account_id
      cloudtrail.set_cloudtrail_s3_iam_policy(account_id, bucket_name)
      cloudwatch_log_hash = cloudtrail.create_cloudtrail_cloudwatch_log(account_id)
      cloudtrail.create_cloudtrail(bucket_name, cloudwatch_log_hash, account_id)
      puts "Please enter your email to receive alarms:"
      email = gets.chomp()
      topic_arn = cloudtrail.create_cloudwatch_alarm_topic(email)

      filter = %Q<{ ( ($.eventSource = "iam.amazonaws.com") && (($.eventName = "Add*") || ($.eventName = "Change*") || ($.eventName = "Create*") || ($.eventName = "Deactivate*") || ($.eventName = "Delete*") || ($.eventName = "Enable*") || ($.eventName = "Put*") || ($.eventName = "Remove*") || ($.eventName = "Update*") || ($.eventName = "Upload*")) ) }>

      puts "Enter a name for your filter and alarm. For this demo, the filter is hard coded to IAM changes"
      filter_name = gets.chomp
      cloudtrail.create_cloudwatch_cloudtrail_filter(filter, filter_name)
      cloudtrail.create_cloudwatch_cloudtrail_alarm(filter_name, topic_arn)

      puts "If you see this, it probably worked. Wait a minute, make an IAM change, and you should see an alarm within 15 minutes."
      puts "Please remember to shut down the services at the end of the lab:"
      puts "  - disable the CloudTrail logging"
      puts "  - Delete the S3 bucket"
      puts "  - Delete the CloudWatch log"
      puts "  - Delete the IAM role"
      puts "  - Delete the SNS topic"
    elsif menuselect == "5"
      cloudtrail = CloudTrailAlarm.new()
      puts "\e[H\e[2J"
      puts "This will delete the trail in your current region."
      puts "No data will be deleted, but you will lose all settings."
      puts "Hit Enter if you really want to do this: "
      blah = gets.chomp()
      cloudtrail.disable_cloudtrail
      puts "Press Return to return to the main menu"
      blah = gets.chomp
    elsif menuselect == "7"
      menuselect = 7
    else 
      puts "Error, please select a valid option"
    end
  end
      
