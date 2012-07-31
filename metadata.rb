maintainer       "Rackspace Us, Inc."
license          "Apache 2.0"
description      "Installs and Configures dsh"
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
version          "0.0.4"

%w{ ubuntu fedora }.each do |os|
  supports os
end

%w{ osops-utils }.each do |dep|
  depends dep
end
