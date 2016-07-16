# This material was created by rmogull@securosis.com for the Black Hat trainings run by Securosis.
# Copyright 2016 Rich Mogull and Securosis, LLC. with a Creative Commons Attribution, NonCommercial, Share Alike license- http://creativecommons.org/licenses/by-nc-sa/4.0/

# Install the listed gems.

require "rubygems"
require 'aws-sdk'
require "json"

# class for incident resposne functions like quarantine.
class Challenge1
  def initialize(instance_id)
    @instance_id = instance_id
    
    # Load configuration and credentials from a JSON file. Right now hardcoded to config.json in the app drectory.
    # Note that we use the same configuration file for multiple code snippet files, but this will only pull what you need.
    
    # configfile = File.read('config.json')
    # config = JSON.parse(configfile)
    
    # Aws.config = { access_key_id: "#{config["aws"]["AccessKey"]}", secret_access_key: "#{config["aws"]["SecretKey"]}", region: "us-west-2" }
    
    @@ec2 = Aws::EC2::Client.new(region: "#{$region}")
  end
  
  def list
    # method to pull all details of all instances in the region.
    
    instancelist = @@ec2.describe_instances()
    
  end
  
  def list_by_tag

    instancelist = @@ec2.describe_tags(
    filters: [
    {
      name: "key",
      values: ["SecurityStatus"]
    }
    ]
    )

  end
  
  def change_sec_group
    # this method moves the provided instance into the Quarantine security group defined in the config file.
    instance_id = ""
    sec_group = ""

   newsecgroup = @@ec2.modify_instance_attribute(instance_id: "#{instance_id}", groups: ["#{sec_group}"])

   end
  
  def store_metadata
    # Method collects the instance metadata before making changes and appends to a local file.
    # Note- currently not working right, need fo convert the has to JSON
    data  = @@ec2.describe_instances(instance_ids: ["#{@instance_id}"])
  
  end
  
  $region = "us-west-2"
  
  