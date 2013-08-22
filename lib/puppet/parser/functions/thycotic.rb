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
# The 'thycotic' module is a Ruby class that retrieves data
# from Thycotic's 'Secret Server' at a given URL with specified credentials.
#
# For security purposes, these credentials are loaded up from a local file
# that must be *manually* placed into /etc/puppet/thycotic
#
# Example Usage:
#   require 'thycotic.rb'
#   thycotic = Thycotic.new( {
#      :username => 'user',
#      :password => 'password',
#      :orgcode  => 'orgcode',
#      :debug    => true,
#      } )
#   secret = thycotic.getSecret(secretid)
#

require 'rubygems'
require 'filecache'
require 'timeout'
require 'yaml'
require 'base64'

# Loading the soap4r gem. This gem overrides the way SSL errors are
# handled in the SOAP code.
gem 'soap4r'
require 'soap/wsdlDriver'

# Some static variables that control the overall behavior of the module
SHORT_TERM_CACHE_TIMEOUT=1800
SHORT_TERM_CACHE_NAME='thycotic'
LONG_TERM_CACHE_TIMEOUT=108000
LONG_TERM_CACHE_NAME='thycotic-long-term'
CACHE_PATH='/tmp'

# For reliability during startup we store a local copy of the Secret Server
# SOAP file named 'WSDL'. This is the default file used during startup and
# configures the app to connect to the public Secret Server service. If a
# unique WSDL URL is supplied instead, then this file is ignored.
SERVICEURL=File.join(File.dirname(__FILE__), 'WSDL')
SOAP_NAMESPACE='urn:thesecretserver.com'

# Disable SOAP4R spurious warnings/etc.
$VERBOSE=nil

# The 'thycotic' class is used to retrieve passwords/keys from the Thycotic SecretServer Online
# by using their API.
class Thycotic
  # This is the class object initializer for this Thycotic interface
  #
  # * *Args*:
  #   - *params* -> A hash with the following keys:
  #     - +username+ -> The login username
  #     - +password+ -> The login password
  #     - +orgcode+ -> The login organization code associated with the above login
  #     - +domain+ ->  The login 'domain' that the above credentials are associated with
  #     - +serviceurl+ -> The remote web services URL
  #                     (default: https://www.secretserveronline.com/webservices/SSWebService.asmx)
  #     - +debug+ -> Should debug logging be enabled (strongly recommend you disable this, very insecure!)
  #                (default: false)
  #     - +cache_path+ -> Filesystem location to cache results (default: /tmp)
  #
  def initialize(params)
    # Fill in any missing parameters to the supplied parameters hash
    @params = params
    @params[:serviceurl] ||= SERVICEURL
    @params[:cache_path] ||= CACHE_PATH
    @params[:debug]      ||= false

    # If debug logging is enabled, we log out our entire parameters dict,
    # including the password/username that were supplied. Debug mode is
    # dangerous and meant to only be used during troubleshooting.
    @params.each do |k,v|
      if k != :password
        puts "Initialization params: #{k} => #{v}" if @params[:debug]
      end
    end

    # Make sure that the required parameters WERE supplied
    if @params[:username].nil? \
            or @params[:password].nil? \
            or @params[:orgcode].nil?
       raise 'Missing parameters. See header above for instructions.'
    end

    # Make sure that a short-term and long-term file cache is available.
    if not @params[:cache_path].nil?
      puts "Initializing short-term cache in" \
           " #{@params[:cache_path]}/#{SHORT_TERM_CACHE_NAME} with timeout" \
           " #{SHORT_TERM_CACHE_TIMEOUT} seconds" if @params[:debug]
      @cache = FileCache.new(SHORT_TERM_CACHE_NAME,
                             @params[:cache_path],
                             SHORT_TERM_CACHE_TIMEOUT)

      puts "Initializing long-term cache in" \
           " #{@params[:cache_path]}/#{LONG_TERM_CACHE_NAME} with timeout" \
           " #{LONG_TERM_CACHE_TIMEOUT} seconds" if @params[:debug]
      @long_term_cache = FileCache.new(LONG_TERM_CACHE_NAME,
                                       @params[:cache_path],
                                       LONG_TERM_CACHE_TIMEOUT)
    end

    # Initialize the SOAP driver -- all uses of the driver call getDriver()
    # but this pre-initializes it at the first use of this object.
    getDriver()
  end

  def getFile(secretid, fileid)
    # This method retreives file contents from the Secret Server with
    # the supplied Secret ID and FileID. This is meant to be used
    # as an internal method by the getSecret() method.
    #
    # * *Args*:
    #   - +secretid+ -> The secret ID that the file belongs to
    #   - +fileid+ -> The file ID to download
    #
    # * *Returns*:
    #   - String containing the ocntents of the downloaded file
    #
    # * *Raises*:
    #   - An exception if the File cannot be downloaded for some reason
    #     after 3 retries.
    #
    tries = 0
    max_tries = 3
    begin
      # Parameters for our SOAP request
      params = {
        :token        => getToken(),
        :secretId     => secretid,
        :secretItemId => fileid,
      }
      resp = getDriver().DownloadFileAttachmentByItemId(params)

      # First find out if we errored out for any reason. If so, fail to
      # return a result and instead raise an exception.
      error = resp['DownloadFileAttachmentByItemIdResult']['Errors']['string']
      if error.to_s == 'File attachment not found.'
        # There is no atual data to return, but this is not a bad thing. There simply is no
        # key... so return false.
        puts "SecretItemId #{fileid} empty, returning empty string." if @params[:debug]
        return ''
      end

      if not error.nil?
        raise "Error retrieving SecretItemId #{fileid}, Secret #{secretid}: " \
              "#{error}"
      end

      # Return the Base64 decoded contents of the FileAttachment data
      encoded_contents = resp['DownloadFileAttachmentByItemIdResult']['FileAttachment']
      decoded_contents = Base64.decode64(encoded_contents).to_s
      puts "SecretItemId #{fileid} file retrieved...\n" if @params[:debug]
      return decoded_contents
    rescue Exception=>e
      puts "SecretItemId #{fileid} retrieval failed: #{e}"
      if tries < max_tries
        tries = tries + 1
        puts "(#{tries}/#{max_tries}) Trying again..."
        retry
      end

      # If we tried too many times, raise an exception.
      raise "SecretItemId #{fileid} retrieval failed too many times: #{e}"
    end
  end

  def getSecret(secretid)
    # The logic here is that our secrets change very rarely.. therefore we'd rather pull from
    # cache almost every time than go out to the remote service and get the secret content. The
    # flow is this:
    #
    # is item in cache and not expired?
    # .. no?
    # .. .. Get item from API. Cache item. Successfull?
    # .. .. no? try returning item from long_term_cache
    # .. .. yes? return item from api, update cache.
    # .. yes?
    # .. .. return item from cache
    #
    if @cache.get(secretid) == nil
      # Get the item from API...
      begin
        token = getToken()
        url = "#{@serviceurl}/GetSecret?token=#{token}&secretId=#{secretid}"
        puts "getSecret(#{secretid}): calling makeRequest(#{url})\n" if @debug
        data = makeRequest(url)

        # We get a massive hash returned from Thyucotic.. strip it down
        secret_hash = {}
        data['Secret'][0]['Items'][0]['SecretItem'].each do |secret|
          if secret.has_key?('FieldDisplayName')
            # In the event that we're looking at a File resource, we need to download the file.
            if secret['IsFile'][0] == 'true'
              content = getFile(secretid,secret['Id'][0],token)
            else
              content = secret['Value'][0]
            end

            if content != false
              puts "getSecret(#{secretid}): Got content for secret '#{secret['FieldDisplayName'][0]}'...\n" if @debug
              secret_hash[secret['FieldDisplayName'][0]] = content
            end
          end
        end

        # Never cache a 'nil' result. Ever.
        if secret_hash != nil
          # Now that we have the item, cache it.. then return it. We cache in two
          # caches because one is used as a 'backup' in case the API service is unavailable
          # for a long period of time.
          puts "getSecret(#{secretid}): Caching secret '#{secretid}'...\n" if @debug
          @cache.set(secretid,secret_hash.to_yaml)
          @long_term_cache.set(secretid,secret_hash.to_yaml)
          return secret_hash
        else
          raise "Retrieved secret was 'nil'. Invalid."
        end
      rescue Exception=>e
        # Last shot.. item was not in our regular cache, AND we couldn't get it
        # from the API service, so lets attempt to find it in our long term cache.
	begin
          puts "getSecret(#{secretid}): Secret unavailable from remote service (#{e}). Found secret in long-term cache. Returning Secret....\n" if @debug
          return YAML::load(@long_term_cache.get(secretid))
	rescue Exception =>e
	  raise "Could not retrieve secret from short or long_term cache, or the API services. Please troubleshoot: #{e}"
	end
      end
    else
      # The item was found in the cache...
      puts "getSecret(#{secretid}): Secret found in short-term cache... Returning Secret....\n" if @debug
      return YAML::load(@cache.get(secretid))
    end
  end

  def checkToken(token)
    # * *Args*:
    #   - +secretid+ -> Secret ID to retrieve
    #
    # * *Returns*:
    #   - Hash containing key/value pairs from the secret retrieved looking like:
    #       hash = {
    #         "<secret field name>" = "<secret content>"
    #         "<secret field name>" = "<secret content>"
    #         "<secret field name>" = "<secret content>"
    #       }
    #
    # * *Raises*:
    #   - An exception in the event that the secret cannot be retrieved
    #

    # First do a quick check and see if the cache is enabled, and if the
    # item exists in the cache already.
    if not @cache.nil? and not @cache.get(secretid).nil?
      # The item was found in the cache...
      puts "Found Secret ID #{secretid} in short term cache." if @params[:debug]
      return YAML::load(@cache.get(secretid))
    end

    # Get the item from API... Wrap the entire thing in a big begin/rescue
    # block and leverage the long_term cache if necessary.
    begin
      # Attempt to get the secret from Thycotic directly
      params = {
        :token    => getToken(),
        :secretId => secretid,
      }
      resp = getDriver().GetSecret(params)

      # First find out if we errored out for any reason. If so, fail to
      # return a result and instead raise an exception.
      if not resp['GetSecretResult']['Errors']['string'].nil?
        raise "Error retrieving Secret ID #{secretid}: "\
              "#{resp['GetSecretResult']['Errors']['string']}"
      end

      # From Thycotic we are returned a rather large hash of all kinds of
      # data, but we really only want to return a few pieces. We dynamically
      # create a new Hash object here that looks like:
      #
      # hash = {
      #   "<secret field name>" = "<secret content>"
      #   "<secret field name>" = "<secret content>"
      #   "<secret field name>" = "<secret content>"
      # }
      #
      # In the event that any of the secret items returned are references to
      # files, we go off and get those files and put the contents of the file
      # into the hash.

      # Define the new Hash
      secret_hash = Hash.new

      # Now for each element returned in the SecretItems XML section add
      # it to the above hash.
     resp['GetSecretResult']['Secret']['Items']['SecretItem'].each do |s|

        # Make sure the secret supplied has a field name... if not, then
        # its likely bogus data.
        if not s['FieldDisplayName'].nil?

          # In the event that we're looking at a File resource, we need to download the file.
          if s['IsFile'] == 'true'
            content = getFile(secretid, s['Id'])
          else
            content = s['Value']
          end

          # If the content is 'nil', then the secret cannot possibly have held a value, so it
          # msut be bogus return data. Even an empty secret will return a blank string.
          if not content.nil?
            puts "Got secret content for Secret ID (#{secretid}/#{s['FieldDisplayName']})...\n" if @params[:debug]
            secret_hash[s['FieldDisplayName']] = content
          end
        end
       end

     # If no secret data was returned at all, something bad happened
     if secret_hash.nil?
        raise "Retrieved secret was 'nil'. Invalid."
     end

     # If the cache is enabled, then cache the secret_hash data.
     if not @cache.nil? and not @long_term_cache.nil?
       puts "Caching Secret ID '#{secretid}'...\n" if @params[:debug]
        @cache.set(secretid,secret_hash.to_yaml)
        @long_term_cache.set(secretid,secret_hash.to_yaml)
      end

      # If we made it here, return the secret_hash data
      return secret_hash

    rescue Exception=>e
      # Last shot.. item was not in our regular cache, AND we couldn't get it
      # from the API service, so lets attempt to find it in our long term cache.
      puts "Secret ID #{secretid} unavailable from API: #{e}" if @params[:debug]
      begin
        secret_hash = YAML::load(@long_term_cache.get(secretid))
        puts "Found secret in long-term cache.\n"
      rescue Exception =>e
        raise "Could not retrieve secret from short or long_term cache, " \
              "or the API services. Please troubleshoot: #{e}"
      end
    end
  end

  def getToken()
    # Check if we have a token available in the cache or not.
    #
    # *Returns* :
    #   - A string representing the current authenticated login token
    #

    # This entire method is basically wrapped in a begin/rescue block
    # so we can easily catch errors in the @cache calls as well as the
    # getTokenIsValid() call to the remote service. Basically any failure
    # here will raise an exception and trigger a new API token to be
    # retrieved.

    begin
      # To save back-and-forth calls to the API, once this object has a
      # authentication token, we store it locally in the object as an
      # object level variable.
      #
      # If a local token has already been saved to the object, move
      # on to checking whether or not its valid.
      if @token.nil?
        # If @cache.get('token') fails for any reason, we're caught by
        # the 'rescue' statement below and a new token is generated.
        @token = @cache.get('token')
      end

      # TODO(mwise): Provide some super-short term cache on the token
      # validity. if it was valid within the last XX seconds, don't
      # bother checking its validity again.

      # Now, check if the token is valid or not...
      resp = getDriver().GetTokenIsValid(:token => @token)
      if resp['GetTokenIsValidResult']['Errors']['string'].nil?
        puts "Found valid token" if @params[:debug]
        return @token
      else
        puts "Found expired token in cache, fetching new..." if @params[:debug]
        raise
      end
    rescue
      # Create the parameters used to generate a login token
      parameters = {
        :username     => @params[:username],
        :password     => @params[:password],
        :organization => @params[:orgcode],
        :domain       => '',
      }

      tries=0
      max_tries=3
      begin
        data = getDriver().Authenticate(parameters)
        token = data['AuthenticateResult']['Token']
        puts "Fetched new token #{token}..." if @params[:debug]
      rescue Exception=>e
        puts "Could not retrieve authentication token: #{e}"
        if tries < max_tries
          tries = tries + 1
          puts "#{tries}/#{max_tries}) Trying again..."
          retry
        end
        puts 'Failed to retrieve token.'
        raise
      end

      # Before returning the token, cache it (if there is a local cache)
      if not @cache.nil?
        puts "Saving token to cache..." if @params[:debug]
        @cache.set('token', @token)
      end

      # Save the token to our local object to prevent getting it again
      @token = token

      # Now return the token
      return token
    end
  end

  def getDriver()
    # This method initializes the SOAP driver if it has not already been
    # configured. The first time this method runs it conncts to the remove
    # service WSDL page and dynamically generates the SOAP methods that
    # can be used. This can take a second, but is only done once.
    #
    # If the initial connection fails multiple times, we give up. Future
    # calls to getDriver() will try again automatically.
    #
    # *Returns* :
    #   - A SOAP Driver object configured with the remote service APIs

    # If the driver is already setup, just return quietly
    if not @driver.nil?
      return @driver
    end

    # Configure the basic WSDL Soap Driver. This initializes the driver
    # and then downloads all of the methods from the provider.
    tries = 0
    max_tries = 3
    begin
      @driver = SOAP::WSDLDriverFactory.new(@params[:serviceurl]).create_rpc_driver
      return @driver
    rescue Exception=>e
      puts "Could not create SOAP Driver from URL #{@params[:serviceurl]}: #{e}"
      if tries < max_tries
        tries = tries + 1
        puts "(#{tries}/#{max_tries}) Trying again..."
        retry
      end
      puts "Failed to log into #{@params[:serviceurl]}. Returning 'nil' object for now."
      return nil
    end
  end
end
