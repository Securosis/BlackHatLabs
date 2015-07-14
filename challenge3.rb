# This material was created by rmogull@securosis.com for the Black Hat trainings run by Securosis.
# Copyright 2014 Rich Mogull and Securosis, LLC. with a Creative Commons Attribution, NonCommercial, Share Alike license- http://creativecommons.org/licenses/by-nc-sa/4.0/

# Install the listed gems.

require "rubygems"
require "aws-sdk"
require "ridley"
require "json"

# This code snippet includes the pieces to pull information from your Chef server. The rest is up to you. As with the other code snippets, you can always see how we did it by looking at the SecuritySquirrel tool on GitHub.

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
