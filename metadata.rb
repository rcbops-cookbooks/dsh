name             "dsh"
maintainer       "Rackspace Us, Inc."
maintainer_email "rcb-deploy@lists.rackspace.com"
license          "Apache 2.0"
description      "Installs and Configures dsh"
long_description IO.read(File.join(File.dirname(__FILE__), "README.md"))
version          IO.read(File.join(File.dirname(__FILE__), 'VERSION'))

%w{ amazon centos debian fedora oracle redhat scientific ubuntu }.each do |os|
  supports os
end

%w{ osops-utils }.each do |dep|
  depends dep
end

recipe "dsh::admin",
  "Installs and configures dsh admin users"

recipe "dsh::member",
  "Installs and configures dsh member users"

attribute "dsh/groups",
  :description => "The dsh groups",
  :default => "[]"

attribute "dsh/admin_groups",
  :description => "The dsh admin groups",
  :default => "[]"

attribute "dsh/host_key",
  :description => "The dsh host key on member servers",
  :default => ""

attribute "dsh/hosts",
  :description => "The dsh hosts information",
  :default => "[]"
