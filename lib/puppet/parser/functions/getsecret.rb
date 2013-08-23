#!/usr/bin/ruby
#
# Copyright 2012 Nextdoor.com, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# The 'getsecret' function uses the Thycotic Secret Server API to retrieve
# private data (passwords, private keys, etc) and returns it to the caller
# as string data.
#
# For setup and usage instructions please see the README in the root of
# the module. Very basic usage instructions are here:
#
# Example usage:
#   $aws_creds = getsecret('539820', 'secret_name')
#
# Returns:
#   $aws_creds = 'foo'

require 'rubygems'
require 'parseconfig'
require File.join(File.dirname(__FILE__), 'thycotic.rb')

# We will store our single Thycotic object here once its created
# in an INSTANCE scoped variable.
@thycotic = nil

# Store a reference to where we loaded our last configuration file
# from. This is used to re-configure our Thycotic object in the event
# that someone calls the getsecret() function with a unique config
# filename. For example:
#
# getsecret(123, 'password')
# ...
# getsecret(234, 'password', '/path/to/corp/thycotic.conf')
#
$last_thycotic_config_file = nil

def init(custom_config=nil)
  # Initializes the configuration for this function. In order to avoid
  # constantly creating new Thycotic API access objects, we store one
  # globally once we've created it.
  #
  # * *Returns*:
  #   A Thycotic object that has been fully configured
  #
  
  # By default, this method looks for the thycotic.conf file in the following
  # filesystem locations:
  #
  #   /etc/puppet/thycotic.conf
  #   <local path to this file>/thycotic.conf
  #
  # However, if a custom_config file parameter is supplied, then we use that
  # file instead.
  possible_paths = [
    "#{lookupvar('thycotic_configpath')}/thycotic.conf",
    "/etc/puppet/thycotic.conf",
    File.join(File.dirname(__FILE__), 'thycotic.conf') ]

  if not custom_config.nil?
    possible_paths = custom_config
  end

  possible_paths.each do |p|
    begin
      @cfg_file = ParseConfig.new(p)
      $last_thycotic_config_file = p
      break
    rescue Exception=>e
      # Just move on.. We will catch the error with a check below
    end
  end

  # Ws the config file even loaded?
  if @cfg_file.nil?
    raise Puppet::ParseError, "Could not load configuration. Please see " \
      "README. Supplied config paths: #{p}."
  end

   # Check for the config file and pull the variables that were supplied.
  begin
    config = {
      :username => @cfg_file['username'],
      :password => @cfg_file['password'],
      :orgcode  => @cfg_file['orgcode'], }
  rescue Exception=>e
    raise Puppet::ParseError, "Missing configuration options in thycotic.conf: #{e}"
  end

  # Now look for optional variables. If they're found, use them. If not, use
  # some defaults
  config[:serviceurl] = @cfg_file['wsdl'] if not @cfg_file['wsdl'].nil?
  config[:cache_path] = @cfg_file['cache_path'] if not @cfg_file['cache_path'].nil?
  config[:debug]      = true if @cfg_file['debug'] == 'true'

  # Create the Thycotic API object
  return Thycotic.new(config)
end


module Puppet::Parser::Functions
  newfunction(:getsecret, :type => :rvalue) do |args|
    secret_id   = args[0]
    secret_name = args[1]
    config      = args[2]

    # Make sure that the minimum arguments were supplied.
    if args.count < 2
      raise Puppet::ParseError, 'Missing arguments. See README for usage.'
    end

    # When running Puppet unit/catalog tests, it often doesn't make sense to error
    # out because the 'getsecret' module isn't configured. Its highly likely that
    # where these unittests are executing the thycotic.conf file has not even been
    # created because it contains secure data.
    #
    # We search for the 'unittest' fact to be set, and if it exists we always return
    # back static data.
    if lookupvar('unittest')
      return 'UNIT_TEST_RESULTS'
    end

    # Figure out if the last time that the @thycotic object was created it used
    # the same config file as the one that was just now supplied. If they are
    # different, then wipe out our object and let it get recreated. This allows
    # for multiple configuration files to be used at the expense of a small
    # amount of performance (recreation of the @thycotic Object below)
    if not config.nil? and config != $last_thycotic_config_file
      @thycotic = nil
    end

    # Create our Thycotic object if it doesn't already exist
    # Look for our config file in a few locations (in order):
    begin
      @thycotic ||= init(config)
    rescue Exception=>e
      raise Puppet::ParseError, "Could not initialize Thycotic object: #{e}"
    end

    # Now request our secret
    secret = @thycotic.getSecret(secret_id)

    # Walk through the returned elements of the hash, and look for the one we want.
    if secret.has_key?(secret_name)
      if secret.has_key?(secret_name) == nil
        raise Puppet::ParseError, "Secret returned by Thycotic.getSecret(#{secretid}) was 'nil'. This is bad, erroring out."
      else
        return secret[secret_name].to_s
      end
    end

    raise Puppet::ParseError, "Could not retrieve SecretID #{secretid}."
  end
end
