# This material was created by rmogull@securosis.com for the Black Hat trainings run by Securosis.
# Copyright 2014 Rich Mogull and Securosis, LLC. with a Creative Commons Attribution, NonCommercial, Share Alike license- http://creativecommons.org/licenses/by-nc-sa/4.0/

# Install the listed gems.

require "rubygems"
require 'aws-sdk-core'
require "json"

# class for incident response functions like quarantine.
class IncidentResponse
  def initialize(instance_id)
    @instance_id = instance_id
    
    # Load configuration and credentials from a JSON file. Right now hardcoded to config.json in the app drectory.
    configfile = File.read('config.json')
    config = JSON.parse(configfile)
    
    @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-west-2"]["QuarantineSecurityGroup"]}"
    @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-west-2"]["AMI"]}"
    @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-west-2"]["AnalysisSecurityGroup"]}"
    @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-west-2"]["SSHKey"]}"
    @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-west-2"]["User"]}"
    
    Aws.config = { access_key_id: "#{config["aws"]["AccessKey"]}", secret_access_key: "#{config["aws"]["SecretKey"]}", region: "us-west-2" }
    
    @@ec2 = Aws::EC2.new
    @@ec2 = Aws.ec2
  end
  
  def quarantine
    # this method moves the provided instance into the Quarantine security group defined in the config file.
    puts ""
    puts "Quarantining #{@instance_id}..."
   quarantine = @@ec2.modify_instance_attribute(instance_id: "#{@instance_id}", groups: ["#{@QuarantineGroup}"])
   puts "#{@instance_id} moved to the Quarantine security group from your configuration settings."
   end
  
  def tag
    # this method adds an "status => IR" tag to the instance.
    # If you properly configure your IAM policies, this will move ownership fo the instance to the security
    # team and isolate it so no one else can terminate/stop/modify/etc.
    puts "Tagging instance with 'IR'..."
    tag = @@ec2.create_tags(resources: ["#{@instance_id}"], tags: [
    {
      key: "SecurityStatus",
      value: "IR",
    },
  ],)
  puts "Instance tagged and IAM restrictions applied."
  end
  
  def snapshot
    # This method determines the volume IDs for the instance, then creates snapshots of those def volumes(args)
    # Get the instance details for the instance
    instance_details = @@ec2.describe_instances(
      instance_ids: ["#{@instance_id}"],
    )
    # find the attached block devices, then the ebs volumes, then the volume ID for each EBS volume. This involves walking the response tree.
    # There is probably a better way to do this in Ruby, but I'm still learning.
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
      snap = @@ec2.create_snapshot(
        volume_id: "#{vol}",
        description: "IR volume #{vol} of instance #{@instance_id} at #{timestamp}",
      )
      puts "Snapshots complete with description: IR volume #{vol} of instance #{@instance_id}  at #{timestamp}"
      # get the snapshot id and add it to an array for this instance of the class so we can use it later for forensics
      @snap = @snap += snap.map(&:snapshot_id)
      
    end
  end
  

  def forensics_analysis
    # This method launches an instance and then creates and attaches storage volumes of the IR snapshots. 
    # It also opens Security Group access between the forensics and target instance.
    # Right now it is in Main, but later I will update to run it as a thread, after I get the code working.
    
    # set starting variables 
    alpha = ("f".."z").to_a
    count = 0
    block_device_map = Array.new
    
    # Build the content for the block device mappings to add each snapshot as a volume. 
    # Device mappings start as sdf and continue up to sdz, which is way more than you will ever need.
    @snap.each do |snapshot_id|
      count += 1
      # pull details to get the volume size
      snap_details = @@ec2.describe_snapshots(snapshot_ids: ["#{snapshot_id}"])
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
    puts "Press Return to return to the main menu"
    blah = gets.chomp
    
    # Create array to get the snapshot status via API

    snaparray = Array.new
    @snap.each do |snap_id|
      snaparray << "#{snap_id}"
    end 
    
    # Launch the rest as a thread since waiting for the snapshot may otherwise slow the program down.
    
    thread = Thread.new do
          # Get status of snapshots and check to see if any of them are still pending. Loop until they are all ready.
        status = false
        until status == true do
          snap_details = @@ec2.describe_snapshots(snapshot_ids: snaparray)
          snap_details.each do |snapID|
            if snap_details.snapshots.first.state == "completed"
              status = true
            else
              status = false
            end
          end
        end
    
        forensic_instance = @@ec2.run_instances(
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
        tag = @@ec2.create_tags(
          resources: ["#{temp_id}"],
          tags: [
            {
              key: "SecurityStatus",
              value: "Forensic Analysis Server for #{@instance_id}",
            },
            {
              key: "Name",
              value: "Forensics",
            },
          ],
        )
      end

  end
  
  def store_metadata
    # Method collects the instance metadata before making changes and appends to a local file.
    # Note- currently not working right, need fo convert the has to JSON
    data  = @@ec2.describe_instances(instance_ids: ["#{@instance_id}"])
    timestamp = Time.new
    File.open("ForensicMetadataLog.txt", "a") do |log|
      log.puts "****************************************************************************************"
      log.puts "Incident for instance #{@instance_id} at #{timestamp}"
      log.puts "****************************************************************************************"
      log.puts ""
      metadata = data.to_h
      metadata = metadata.to_json
      log.puts metadata
    end
    puts "Metadata for #{@instance_id} appended to ForensicMetadataLog.txt"
  end
  
  
end

