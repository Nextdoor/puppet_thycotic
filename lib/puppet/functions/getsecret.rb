#!/usr/bin/ruby

require 'parseconfig'
require 'rubygems'
require File.join(File.dirname(__FILE__), 'thycotic.rb')

module Puppet::Parser::Functions

  Puppet::Functions.create_function(:getsecret) do

    def init(custom_config = nil)
      possible_paths = [
        "#{Facter.value('thycotic_configpath')}/thycotic.conf",
        '/etc/puppetlabs/puppet/thycotic.conf',
        '/etc/puppet/thycotic.conf',
        File.join(File.dirname(__FILE__), 'thycotic.conf')
      ]

      possible_paths = custom_config unless custom_config.nil?

      possible_paths.each do |p|
        begin
          @cfg_file = ParseConfig.new(p)
          $last_thycotic_config_file = p
          break
        rescue Exception => e
          # Just move on.. We will catch the error with a check below
        end
      end

      # Was the config file even loaded?
      if @cfg_file.nil?
        raise Puppet::ParseError, 'Could not load configuration. Please see ' \
            "README. Supplied config paths: #{p}."
      end

      # Check for the config file and pull the variables that were supplied.
      begin
        config = {
          username: @cfg_file['username'],
          password: @cfg_file['password'],
          orgcode: @cfg_file['orgcode']
        }
        rescue Exception => e
          raise Puppet::ParseError, "Missing configuration options in thycotic.conf: #{e}"
        end

        # Now look for optional variables. If they're found, use them. If not, use
        # some defaults
        config[:serviceurl] = @cfg_file['wsdl'] unless @cfg_file['wsdl'].nil?
        config[:cache_path] = @cfg_file['cache_path'] unless @cfg_file['cache_path'].nil?
        config[:cache_owner] = @cfg_file['cache_owner'] unless @cfg_file['cache_owner'].nil?
        config[:cache_group] = @cfg_file['cache_group'] unless @cfg_file['cache_group'].nil?
        config[:domain] = @cfg_file['domain'] unless @cfg_file['domain'].nil?
        config[:debug] = true if @cfg_file['debug'] == 'true'

        # Create the Thycotic API object
        Thycotic.new(config)
    end

    def getsecret(*arguments)
      secret_id = arguments[0]
      secret_name = arguments[1]
      config      = arguments[2]

      # Make sure that the minimum arguments were supplied.
      if arguments.count < 2
        raise Puppet::ParseError, 'Missing arguments. See README for usage.'
      end

      # When running Puppet unit/catalog tests, it often doesn't make sense to error
      # out because the 'getsecret' module isn't configured. Its highly likely that
      # where these unittests are executing the thycotic.conf file has not even been
      # created because it contains secure data.
      #
      # We search for the 'unittest' fact to be set, and if it exists we always return
      # back static data.
      return 'UNIT_TEST_RESULTS' if Facter.value('unittest')

      # Figure out if the last time that the @thycotic object was created it used
      # the same config file as the one that was just now supplied. If they are
      # different, then wipe out our object and let it get recreated. This allows
      # for multiple configuration files to be used at the expense of a small
      # amount of performance (recreation of the @thycotic Object below)
      @thycotic = nil if !config.nil? && config != $last_thycotic_config_file

      # Create our Thycotic object if it doesn't already exist
      # Look for our config file in a few locations (in order):
      begin
        @thycotic ||= init(config)
      rescue Exception => e
        raise Puppet::ParseError, "Could not initialize Thycotic object: #{e}"
      end

      # Now request our secret
      Puppet.debug "#{Facter.value('fqdn')} requested #{secret_id}"
      secret = @thycotic.getSecret(secret_id)

      # Walk through the returned elements of the hash, and look for the one we want.
      if secret.key?(secret_name)
        if secret.key?(secret_name).nil?
          raise Puppet::ParseError, "Secret returned by Thycotic.getSecret(#{secret_id}) was 'nil'. This is bad, erroring out."
        else
          return secret[secret_name].to_s
        end
      end

      raise Puppet::ParseError, "Could not retrieve SecretID #{secret_id}."
    end
  end
end
