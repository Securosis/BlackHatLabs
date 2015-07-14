# SecDevOps Toolkit code by rmogull@securosis.com
# Copyright 2014 Rich Mogull and Securosis, LLC. with a Creative Commons Attribution, NonCommercial, Share Alike license- http://creativecommons.org/licenses/by-nc-sa/4.0/

# These code samples are meant to accompany Securosis SecDevOps, CCSK, and other training programs and workshops.
# This is not a complete, functional application.

# To function, you need a properly-formatted config.json file in the same directory as where this code runs.

# You must install the listed gems..


require "rubygems"
require 'bundler/setup'
require "aws-sdk"
require 'aws-sdk-core'
require "json"
require 'open-uri'
require 'netaddr'
require 'ridley'
require 'pry'

class ConfigManagement
  # This class integrates with Chef for configuration management. Right now it only has one method.
  def analyze
    # This method polls EC2 and polls Chef to identify any unmanaged instances.
    # Right now it uses the instance name since there is a bug in the Ridley SDK that limits pulling alternate attribures, but plan is to fix that soon

    # Load configuration and credentials from a JSON file

    # Load from config file in same directory as code
    # In the future, we will need to adjust this to rotate through all accounts and regions for the user. AssumeRole should help.
    config = JSON.load(File.read('config.json'))
    #  credentials... using hard coded for this PoC, but really should be an assumerole in the future.
    creds = Aws::Credentials.new("#{config["aws"]["AccessKey"]}", "#{config["aws"]["SecretKey"]}")
    # Create clients for the various services we need. Loading them all here and setting them as Class variables.
    @ec2 = Aws::EC2::Client.new(credentials: creds, region: "#{$region}")

    # Pull all instances in the region and create an empty array to hold their private DNS names
    instances = @ec2.describe_instances()
    instancelist = []
    # go through each reservation, then each instance, and add the DNS name to the array
    instances.reservations.each do |reservation|
      reservation.instances.each do |instance|
        instancelist << instance.private_dns_name
      end
    end


    # Start a ridley connection to our Chef server. Pull the configuration from our file.

    chefconfig = config["chef"]

    #supress errors since Ridley is buggy; switch to "fatal" if it keeps showing up.
    Ridley::Logging.logger.level = Logger.const_get 'ERROR'
    ridley = Ridley.new(
      server_url: "#{config["chef"]["chefserver"]}",
      client_name: "#{config["chef"]["clientname"]}",
      client_key: "#{config["chef"]["keylocation"]}",
      ssl: { verify: false }
    )

    # Ridley has a bug, so we need to work on the node name, which in our case is the same as the EC2 private DNS. For some reason the node.all doesn't pull IP addresses (it's supposed to) which is what we would prefer to use.
    nodes = ridley.node.all
    nodenames = nodes.map { |node| node.name }

    # For every EC2 instance, see if there is a corresponding Chef node.

    puts ""
    puts ""
    puts "Instance            =>                      managed?"
    puts ""
    instancelist.each do |thisinstance|
      managed = nodenames.include?(thisinstance)
      puts " #{thisinstance} #{managed} "
    end
  end
end


# class for incident response functions like quarantine.
class IncidentResponse
  def initialize()
    # Load configuration and credentials from a JSON file. Right now hardcoded to config.json in the app drectory
    config = JSON.load(File.read('config.json'))
    #  credentials... using hard coded for this PoC, but really should be an assumerole in the future.
    creds = Aws::Credentials.new("#{config["aws"]["AccessKey"]}", "#{config["aws"]["SecretKey"]}")
    # Create clients for the various services we need. Loading them all here and setting them as Class variables.
    @ec2 = Aws::EC2::Client.new(credentials: creds, region: "#{$region}")

    # Set application configuration variables.
    # Remember that not all AWS services are available in all regions. Everything in this version of the tool should work.

    if $region == "us-west-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-west-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-west-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-west-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-west-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-west-1"]["User"]}"
    elsif $region == "us-west-2"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-west-2"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-west-2"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-west-2"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-west-2"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-west-2"]["User"]}"
    elsif $region == "us-east-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-east-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-east-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-east-1"]["User"]}"
    elsif $region == "eu-west-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["eu-west-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["eu-west-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["eu-west-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["eu-west-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["eu-west-1"]["User"]}"
    elsif $region == "ap-southeast-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["User"]}"
    elsif $region == "ap-southeast-2"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["User"]}"
    elsif $region == "ap-northeast-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["User"]}"
    elsif $region == "sa-east-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["sa-east-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["sa-east-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["sa-east-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["sa-east-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["sa-east-1"]["User"]}"
    else
      #default to us-east-1 in case something fails
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-east-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-east-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-east-1"]["User"]}"
    end
  end

  def quarantine(instance_id)
    # this method moves the provided instance into the Quarantine security group defined in the config file.
    puts ""
    puts "Quarantining #{instance_id}..."
    quarantine = @ec2.modify_instance_attribute(instance_id: "#{instance_id}", groups: ["#{@QuarantineGroup}"])
    puts "#{instance_id} moved to the Quarantine security group from your configuration settings."
  end

  def tag(instance_id)
    # this method adds an "status => IR" tag to the instance.
    # If you properly configure your IAM policies, this will move ownership fo the instance to the security
    # team and isolate it so no one else can terminate/stop/modify/etc.
    puts "Tagging instance with 'IR'..."
    tag = @ec2.create_tags(resources: ["#{instance_id}"], tags: [
                             {
                               key: "SecurityStatus",
                               value: "IR",
                             },
    ],)
    puts "Instance tagged and IAM restrictions applied."
  end

  def snapshot(instance_id)
    # This method determines the volume IDs for the instance, then creates snapshots of those def volumes(args)
    # Get the instance details for the instance
    instance_details = @ec2.describe_instances(
      instance_ids: ["#{instance_id}"],
    )

    # find the attached block devices, then the ebs volumes, then the volume ID for each EBS volume. This involves walking the response tree.

    puts "Identifying attached volumes..."
    block_devices = instance_details.reservations.first.instances.first.block_device_mappings
    ebs = block_devices.map(&:ebs)
    volumes = ebs.map(&:volume_id)
    # start an empty array to later track and attach the snapshot to a forensics storage volume
    @snap = []
    volumes.each do |vol|
      puts "Volume #{vol} identified; creating snapshot"
      # Create a snapshot of each volume and add the volume and instance ID to the description.
      # We do this since you can't apply a name tag until the snapshot is created, and we don't want to slow down the process.
      timestamp = Time.new
      snap = @ec2.create_snapshot(
        volume_id: "#{vol}",
        description: "IR volume #{vol} of instance #{instance_id} at #{timestamp}",
      )
      puts "Snapshots complete with description: IR volume #{vol} of instance #{instance_id}  at #{timestamp}"
      # get the snapshot id and add it to an array for this instance of the class so we can use it later for forensics
      @snap = @snap += snap.map(&:snapshot_id)
    end
    # Launch a thread to tag the snapshots with "IR" to restrict to the security team.
    # We do this since we need to wait until the snapshot is created for the tags to work.

    snapthread = Thread.new do
      snap_array = Array.new
      @snap.each do |snap_id|
        snap_array << "#{snap_id}"
      end

      status = false
      until status == true do
          snap_details = @ec2.describe_snapshots(snapshot_ids: snap_array)
          snap_details.each do |snapID|
            if snap_details.snapshots.first.state == "completed"
              status = true
            else
              status = false
            end
          end
        end
        # Tag the snapshot
        @ec2.create_tags(
          resources: snap_array,
          tags: [
            {
              key: "SecurityStatus",
              value: "IR",
            },
          ],
        )

      end
      return @snap
    end


    def forensics_analysis(snapshot_array)
      # This method launches an instance and then creates and attaches storage volumes of the IR snapshots.
      # It also opens Security Group access between the forensics and target instance.

      # set starting variables
      alpha = ("f".."z").to_a
      count = 0
      block_device_map = Array.new

      # Build the content for the block device mappings to add each snapshot as a volume.
      # Device mappings start as sdf and continue up to sdz, which is way more than you will ever need.
      snapshot_array.each do |snapshot_id|
        count += 1
        # pull details to get the volume size
        snap_details = @ec2.describe_snapshots(snapshot_ids: ["#{snapshot_id}"])
        vol_size = snap_details.snapshots.first.volume_size
        # create the string for the device mapping
        device = "/dev/sd" + alpha[count].to_s
        # build the hash we will need later for the bock device mappings
        temphash = Hash.new
        temphash = {
          device_name: "#{device}",
          ebs: {
            snapshot_id: "#{snapshot_id}",
            volume_size: vol_size,
            volume_type: "standard",
          }
        }
        # add the hash to our array
        block_device_map << temphash

      end

      # Notify user that this will run in the background in case the snapshots are large and it takes a while

      puts "A forensics analysis server is being launched in the background in #{@region} with the name"
      puts "'Forensics' and the snapshots attached as volumes starting at /dev/sdf "
      puts "(which may show as /dev/xvdf). Use host key #{@ForensicsSSHKey} for user #{@ForensicsUser}"
      puts ""

      # Create array to get the snapshot status via API

      snaparray = Array.new
      snapshot_array.each do |snap_id|
        snaparray << "#{snap_id}"
      end

      # Launch the rest as a thread since waiting for the snapshot may otherwise slow the program down.

      thread = Thread.new do
        # Get status of snapshots and check to see if any of them are still pending. Loop until they are all ready.
        status = false
        until status == true do
            # wait 5 seconds to reduce API call load
            sleep 5
            snap_details = @ec2.describe_snapshots(snapshot_ids: snaparray)
            snap_details.each do |snapID|
              if snap_details.snapshots.first.state == "completed"
                status = true
              else
                status = false
              end
            end
          end

          forensic_instance = @ec2.run_instances(
            image_id: "#{ @ForensicsAMI}",
            min_count: 1,
            max_count: 1,
            instance_type: "t1.micro",
            key_name: "#{@ForensicsSSHKey}",
            security_group_ids: ["#{@AnalysisSecurityGroup}"],
            placement: {
              availability_zone: "us-west-2a"
            },
            block_device_mappings: block_device_map
          )
          # Tag the instance so you can find it later
          temp_id = forensic_instance.instances.first.instance_id

          tag = @ec2.create_tags(
            resources: ["#{temp_id}"],
            tags: [
              {
                key: "IncidentResponseID",
                value: "Forensic Analysis Server for #{instance_id}",
              },
              {
                key: "SecurityStatus",
                value: "IR",
              },
              {
                key: "Name",
                value: "Forensics",
              },
            ],
          )

          # create variable to store the IR server in the Trinity database
          # TODO store this variable in the database to track later for the incident
          ir_server_details = {:instance_id => "#{instance_id}", :timestamp => timestamp, :incident_id => "placeholder"}
        end

      end

      def store_metadata(instance_id)
        # Method collects the instance metadata and stores as a JSON variable

        data  = @ec2.describe_instances(instance_ids: ["#{instance_id}"])
        timestamp = Time.new
        incident_id = {:timestamp => timestamp, :incident_id => "placeholder"}
        metadata = data.to_h
        metadata = metadata.to_json
        puts "Instance metadata recorded"
      end

      def add_remove_security_group(instance_id, secgroup_id, action)
        # add a security group to the instance

        # get instance details
        instance_details = @ec2.describe_instances(
          instance_ids: ["#{instance_id}"],
        )

        # identify IP and security groups
        puts "Identifying internal IP address..."
        instance_IP = instance_details.reservations.first.instances.first.private_ip_address
        puts "IP address is #{instance_IP}"
        puts ""
        puts "Identifying current security groups..."
        securitygroups = instance_details.reservations.first.instances.first.security_groups
        secgroupID = securitygroups.map(&:group_id)
        puts secgroupID
        puts ""
        if action == "add"
          puts "Adding the new security group"
          secgroupID << secgroup_id
          update_sec_group = @ec2.modify_instance_attribute(instance_id: "#{instance_id}", groups: secgroupID)
          puts "Security group added, instance is now in: #{secgroupID}"
        elsif action == "remove"
          puts "Removing the new security group"
          secgroupID.delete(secgroup_id)
          update_sec_group = @ec2.modify_instance_attribute(instance_id: "#{instance_id}", groups: secgroupID)
          puts "Security group removed, instance is no longer in: #{secgroupID}"
        else
          puts "Invalid action: #{action}"
        end
      end

      def block_ip (instance_id, cidr)
        puts "Determining current subnet for the instance. (Note: this version only works for the primary network interface):"
        metadata  = @ec2.describe_instances(instance_ids: ["#{instance_id}"])
        subnet = metadata.reservations.first.instances.first.subnet_id
        vpc = metadata.reservations.first.instances.first.vpc_id
        puts "Instance is located in subnet #{subnet} of VPC #{vpc}"
        # pull any ACL associated with the VPC
        acl_list = @ec2.describe_network_acls(
          filters: [
            {
              name: "vpc-id",
              values: ["#{vpc}"]
            },
          ],
        )
        # find one associated with the subnet
        acl_list.network_acls.each do |acl|
          # pull the lowest number entry to place our rule before it.
          # TODO eventually, this needs to be smarter and dynamically move the rules around.
          rule_number = 1000000000
          acl.entries.each do |entry|
            if entry.rule_number < rule_number
              rule_number = entry.rule_number
            end
          end
          rule_number = rule_number - 1
          acl.associations.each do |association|
            if association.subnet_id == subnet
              @ec2.create_network_acl_entry(
                network_acl_id: acl.network_acl_id,
                # required
                rule_number: rule_number,
                # required
                protocol: "-1",
                # required
                rule_action: "deny",
                # required
                egress: false,
                # required
                cidr_block: cidr,
              )
              puts "All traffic from #{cidr} blocked for ACL #{acl.network_acl_id} on subnet #{subnet}"
            end
          end
        end

      end
    end

    # class for incident analysis

    class InstanceAnalysis
      def initialize(instance_id)
        instance_id = instance_id

        # Load configuration and credentials from a JSON file. Right now hardcoded to config.json in the app drectory.
        config = JSON.load(File.read('config.json'))
        #  credentials... using hard coded for this PoC, but really should be an assumerole in the future.
        creds = Aws::Credentials.new("#{config["aws"]["AccessKey"]}", "#{config["aws"]["SecretKey"]}")
        # Create clients for the various services we need. Loading them all here and setting them as Class variables.
        @ec2 = Aws::EC2::Client.new(credentials: creds, region: "#{$region}")
        @@autoscaling = Aws::AutoScaling::Client.new(credentials: creds, region: "#{$region}")
        @@loadbalance = elasticloadbalancing = Aws::ElasticLoadBalancing::Client.new(credentials: creds, region: "#{$region}")
        # Load the analysis rules
        @@rules = JSON.load(File.read('analysis_rules.json'))
      end

      # method to determine if instance is in an autoscaling group
      def autoscale(instance_id)
        metadata  = @ec2.describe_instances(instance_ids: ["#{instance_id}"])
        tags = metadata.reservations.first.instances.first
        # covert to hash to make this easier
        tags = tags.to_h
        tags = tags[:tags]
        # quick check to avoid having to iterate through all the tags to see if the one we need is there.
        temp_tags = tags.to_s
        if temp_tags.include?("aws:autoscaling:groupName")
          tags.each do |curtag|
            if curtag[:key] == "aws:autoscaling:groupName"
              @autoscaling = curtag[:value]
            end
          end
        else
          @autoscaling = "false"
        end
      end

      def get_security_groups(instance_id)
        # This method determines the security groups for an instance. It does not check multiple network interfaces.
        # It also determines all the open ports for those groups, and the destinations

        # Pull the security groups for our instance
        metadata  = @ec2.describe_instances(instance_ids: ["#{instance_id}"])

        secgroups = metadata.reservations.first.instances.first.security_groups
        # Get the group IDs
        secgroups = secgroups.map(&:group_id)
        # Now pull the details for all those groups
        secgroups = @ec2.describe_security_groups(group_ids: secgroups)

        @portlist = {}
        @secgrouplist = []
        # interate through each security group
        secgroups.security_groups.each do |group|
          # pull the security group IDs so we can use them later to find connections
          @secgrouplist << group.group_id
          # now pull all the ports into a hash. Start by seeing if port is already on list, if not, add the key
          group.ip_permissions.each do |port|
            if @portlist.has_key?(port.from_port.to_s) == false
              @portlist[port.from_port.to_s] = []
            end
            # Now iterate through the ip ranges to get the ip list
            port.ip_ranges.each do |cidr|
              if cidr.cidr_ip != nil
                tempport = @portlist[port.from_port.to_s]
                tempport << cidr.cidr_ip
                @portlist[port.from_port.to_s] = tempport
              end
            end
            # pull other security groups allowed to connect to this one
            port.user_id_group_pairs.each do |internalsg|
              if internalsg.group_id != nil
                tempport = @portlist[port.from_port.to_s]
                tempport << internalsg.group_id
                @portlist[port.from_port.to_s] = tempport
                # this may be redundent, keeping it for now in case we just want a short list of connected security groups
              end
            end
          end

        end
      end
  end

  def region
    # A method for setting the availability zone
    # Pull the configuration so we only show regions that are configured
    configfile = File.read('config.json')
    config = JSON.parse(configfile)

    puts "\e[H\e[2J"
    puts "Current region: #{$region}. Select a new region:"
    puts "(Only regions you have configured are shown)"
    puts ""
    puts ""

    if config["aws"]["RegionSettings"].has_key?('us-east-1')
      puts "1. us-east-1 (Virginia)"
    end
    if config["aws"]["RegionSettings"].has_key?('us-west-1')
      puts "2. us-west-1 (California)"
    end
    if config["aws"]["RegionSettings"].has_key?('us-west-2')
      puts "3. us-west-2 (Oregon)"
    end
    if config["aws"]["RegionSettings"].has_key?('eu-west-1')
      puts "4. eu-west-1 (Ireland)"
    end
    if config["aws"]["RegionSettings"].has_key?('ap-southeast-1')
      puts "5. ap-southeast-1 (Singapore)"
    end
    if config["aws"]["RegionSettings"].has_key?('ap-southeast-2')
      puts "6. ap-southeast-2 (Sydney)"
    end
    if config["aws"]["RegionSettings"].has_key?('ap-northeast-1')
      puts "7. ap-northeast-1 (Tokyo)"
    end
    if config["aws"]["RegionSettings"].has_key?('sa-east-1')
      puts "8. sa-east-1 (Sao Paulo)"
    end


    puts ""
    print "New region: "
    option = gets.chomp
    $region = case option
    when "1" then "us-east-1"
    when "2" then "us-west-1"
    when "3" then "us-west-2"
    when "4" then "eu-west-1"
    when "5" then "ap-southeast-1"
    when "6" then "ap-southeast-2"
    when "7" then "ap-northeast-1"
    when "8" then "sa-east-1"
    else puts "Error, select again:"
    end

  end

  # Body code
  # Load defaults. Rightnow, just the region.
  configfile = File.read('config.json')
  config = JSON.parse(configfile)
  $region = "#{config["aws"]["DefaultRegion"]}"


  menuselect = 0
  until menuselect == 7 do
      puts "\e[H\e[2J"
      puts "Welcome to the Securosis SecDevOps Learning Lab. Please select an action:"
      puts "Current region is #{$region}"
      puts ""
      puts "1. Run it"
      puts "2. Config Management"
      puts "3. "
      puts "4. "
      puts "5. "
      puts "6. Change region"
      puts "7. Exit"
      puts ""
      print "Select: "
      menuselect = gets.chomp
      if menuselect == "1"
        puts "\e[H\e[2J"
        print "Enter instance ID: "
        instance_id = gets.chomp

        incident_response = IncidentResponse.new()
        incident_response.quarantine(instance_id)
        incident_response.tag(instance_id)
        snap_array = incident_response.snapshot(instance_id)
        incident_response.forensics_analysis(snap_array)
        incident_response.store_metadata(instance_id)
        print "Enter security group ID: "
        secgroup_id = gets.chomp()
        print "Add or remove the security group? (add/remove): "
        action = gets.chomp()
        incident_response.add_remove_security_group(instance_id, secgroup_id, action)
        print "Enter the CIDR to block in the Access Control List: "
        cidr = gets.chomp()
        incident_response.block_ip(instance_id, cidr)

        puts ""
        puts "Press Return to return to the main menu"
        blah = gets.chomp
      elsif menuselect == "2"
        puts "\e[H\e[2J"
        config = ConfigManagement.new()
        config.analyze
        puts "Press Return to return to the main menu"
        blah = gets.chomp
      elsif menuselect == "3"
        puts "\e[H\e[2J"

        puts "Press Return to return to the main menu"
        blah = gets.chomp
      elsif menuselect == "4"
        puts "\e[H\e[2J"
        puts "Press Return to return to the main menu"
        blah = gets.chomp
      elsif menuselect == "5"

        puts "Press Return to return to the main menu"
        blah = gets.chomp
      elsif menuselect == "6"
        region
      elsif menuselect == "7"
        menuselect = 7
      else
        puts "Error, please select a valid option"
      end
    end
