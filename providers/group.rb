action :join do
  ruby_block "set host key attribute" do
    block {
      host_key = ::File.read("/etc/ssh/ssh_host_rsa_key.pub").strip
      node["dsh"]["host_key"] = host_key
    }
  end
  ruby_block "add group attribute" do
    only_if { new_resource.user }
    block { node["dsh"]["groups"][new_resource.name] = new_resource.user }
  end
  ruby_block "generate ssh key" do
    only_if { new_resource.admin_user }
    block {
      home = ::File.expand_path "~#{new_resource.admin_user}"
      privkey_path = "#{home}/.ssh/id_rsa"
      pubkey_path = "#{privkey_path}.pub"
      if not (::File.exists? privkey_path or ::File.exists? pubkey_path)
        #generate ssh key
        system(" ssh-keygen -q -f #{privkey_path} -P \"\"", :in=>"/dev/null")
      end
    }
  end
  ruby_block "add admin attribute" do
    only_if { new_resource.admin_user }
    block {
      home = ::File.expand_path "~#{new_resource.admin_user}"
      pubkey = ::File.read("#{home}/.ssh/id_rsa.pub").strip
      node["dsh"]["admin_groups"][new_resource.name] = {
        "user" => new_resource.admin_user,
        "pubkey" => pubkey
      }
    }
  end
end

action :leave do
  execute "revoke access" do
    command "rm /tmp/#{new_resource.user}"
  end
end
