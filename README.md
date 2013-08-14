# Puppet Plugin: Thycotic Secret Getter

This Puppet plugin allows you to access *secrets* from the Thycotic Secret
Server (either Online edition, or your own in-house hosted edition) from within
your Puppet manifests.

## Description

By allowing you to reference passwords, certificates and other private data from
within your Puppet manifests, but not actually storing that private data within
them, your puppet code becomes readable by a wider audience of team members, and
more secure.

By example, rather than code that says ::

    file { '/etc/mypassword':
      content => 'SillyPassword';
    }

you can obscure the contents of your password by storing them in the Thycotic
Secret Server and accessing them like this ::

    file { '/etc/mypassword':
      content => getsecret('12345','plaintext_password');
    }
    
##  Under the hood

### Thycotic API Access

The `getsecret()` function leverages the `Thycotic` ruby class to make
API calls against the Thycotic secret server. On your Puppet server, a private
configuration file provides the credentials that this plugin uses to access
`The Secret Server.`

The `Thycotic` class is defined in `lib/puppet/parser/functions/thycotic.rb`. It
leverages the Ruby `soap4r` gem to access the Secret Server WSDL file and creates
its SOAP access methods dynamically on startup. For speed and reliability, we've
included the latest copy of the WSDL definitions `lib/puppet/parser/functions/WSDL`
and we load these up by default. If the definitions change though you can point
the library directly to the WSDL URL. This also allows you to point to your own
in-house Secret Server URL.

### Caching for Performance and Reliability

By default the `Thycotic` class creates two local Ruby `filecache`'s in the
`/tmp` filesystem. The default cache is a *short-term* cache used to reduce the
number of API calls your servers make to the Thycotic servers. In a single Puppet
manifest, you may call the `getsecret()` method dozens of times, and it would be
very slow and inneficient to constantly connect to the remote service to get
these values back. Using a local short-term cache (*5 minute TTL*), we store the
authentication Token as well as the secrets for fast access.

Additionally, we create a *long-term* cache that stores our secrets (*30 day TTL*)
in the event that the Secret Server service goes offline for any reason. This
cache is only used in the event that a secret cannot be retrieved first from the
*short-term* cache and second from the actual remote API service.

## Installation and Configuration

Installation is simple... checkout this Git repository into a new module in your
Puppet modules path, and create the configuration file.

### Installation
    cd <your puppet path>/modules
    git clone git@github.com:Nextdoor/puppet_thycotic.git
    gem install bundle
    bundle install

### Configuration

Create the configuration file `/etc/puppet/thycotic.conf`

    # Default configuration parameters
    user = username
    password = password
    orgcode = orgCode
    
    # Optional parameters (defaults shown here)
    # debug = false
    # cache_path = /tmp
    # url = file:///<path to your module>/lib/puppet/parser/functions/WSDL
    
The configuration file can be located in three places by default. It is searched
for in the following order:

- ${thycotic_configpath}/thycotic.conf
- /etc/puppet/thycotic.conf
- <path to module>/lib/puppet/parser/functions/thycotic.conf

The *$thycotic_configpath* variable can be set in your site.pp file, allowing you
to customize the default location of the config file path. The first file that is
found (based on the order above) is the file loaded up and used. All others are
ignored.

## Usage

The most basic usage is calling `getsecret()` with a single `secret_id` and
`secret_name` value. The `secret_id` correlates to a secret within the
Thycotic Secret Server, and the 'name' is the field name within that secret
that you'd like to pull down.

    file { '/etc/mypassword':
      content => getsecret('12345','plaintext_password');
    }
    
In the event that you need to have multiple Thycotic configuration files, you
can do this by passing the configuration file option in as the third parameter.
There is a performance penalty to this, as each time the getsecret() method
is called with a new `config_path` option it will destroy the existing Thycotic
object and recreate it -- this takes some time because SOAP is slow and CPU
intensive.

    file { '/etc/mypassword':
      content => getsecret('12345', 'plaintext_password', '/etc/thycotic.conf')
    }
