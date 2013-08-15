Support
=======

Issues have been disabled for this repository.  
Any issues with this cookbook should be raised here:

[https://github.com/rcbops/chef-cookbooks/issues](https://github.com/rcbops/chef-cookbooks/issues)

Please title the issue as follows:

[dsh]: \<short description of problem\>

In the issue description, please include a longer description of the issue, along with any relevant log/command/error output.  
If logfiles are extremely long, please place the relevant portion into the issue description, and link to a gist containing the entire logfile

Please see the [contribution guidelines](CONTRIBUTING.md) for more information about contributing to this cookbook.

Description
===========
dsh is a lwrp? for setting up dsh group files and mapping permissions between user accounts and administrative users to allow easy bootstrapping of distributed access to a group of nodes via dsh.

Resources/Providers
===================
There's currently one provider, "group", which does all the heavy lifting.

group
-----
The provider uses Chef's search functionality to discover and update the group and user mappings dsh makes use of. Mappings are between accounts on the host system and the the target systems.

# Mappings
- Updates known_hosts on the host system with the target systems
- Updates authorized_keys on the target systems with every admin_user's public key

# Attributes
- group: The dsh group name
- user: The user account to manipulate on the target systems
- admin_user: The admin user account on the host system
- admin_pubkey: (optional) The admin user's public SSH key
- network: (optional) An osops_utils-style network to use instead of the FQDN
- skip_create: An array of users to not create home directories for (defaults to ['root','nova','glance'])

Usage
=====

  dsh_group "testing" do
    user "test2"
    admin_user "test1"
    #provider "dsh_group"  # default?
  end

  # user/admin_user also accept a hash of resource attributes
  dsh_group "testing" do
    user :username => "test2", :uid => 2000, :comment = "Test User 2"
    admin_user "test1"
  end

License and Author
==================

Author:: Justin Shepherd (<justin.shepherd@rackspace.com>)  
Author:: Jason Cannavale (<jason.cannavale@rackspace.com>)  
Author:: Ron Pedde (<ron.pedde@rackspace.com>)  
Author:: Joseph Breu (<joseph.breu@rackspace.com>)  
Author:: William Kelly (<william.kelly@rackspace.com>)  
Author:: Darren Birkett (<darren.birkett@rackspace.co.uk>)  
Author:: Evan Callicoat (<evan.callicoat@rackspace.com>)  
Author:: Chris Laco (<chris.laco@rackspace.com>)
Author:: Brett Campbell (<brett.campbell@rackspace.com>)

Copyright 2012-2013, Rackspace US, Inc.  

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
