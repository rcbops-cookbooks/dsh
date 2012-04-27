action :join do
  users = []
  users.push new_resource.user if new_resource.user
  users.push new_resource.admin_user if new_resource.admin_user
  members = find_dsh_group_members(new_resource.name)
  admins = find_dsh_group_admins(new_resource.name)
  users.each { |u|
    user_p = user u do
      shell "/bin/bash"
      home "/home/#{u}"
    end
    user_p.run_action(:create)
    home = get_home(u)

    d = directory home do
      owner u
      group u
      action :create
    end
    d.run_action(:create)

    d = directory "#{home}/.ssh" do
      only_if { u == new_resource.user }
      owner u
      group u
      action :create
    end
    d.run_action(:create)

    d = directory "#{home}/.ssh" do
      only_if { u == new_resource.admin_user}
      owner u
      action :create
    end
    d.run_action(:create)

    d = directory "#{home}/.dsh/group" do
      only_if { u == new_resource.admin_user}
      owner u
      group u
      recursive true
      action :create
    end
    d.run_action(:create)
    f = file "#{home}/.dsh/group/#{new_resource.name}" do
      only_if { u == new_resource.admin_user}
      owner u
      group u
      action :create
    end
    f.run_action(:create)
  }
  
  Package "dsh" do
    only_if { new_resource.admin_user}
    action :upgrade
  end

  update_host_key
  
  if new_resource.user
    #Member node: allow logins from admin_users
    #Join group by setting appropriate attributes
    node["dsh"]["groups"][new_resource.name] = new_resource.user
    
    #Todo configure authorized_keys
    home = get_home(new_resource.user)
    auth_key_file = "#{home}/.ssh/authorized_keys"
    #members.each { |m| }
    new_resource.updated_by_last_action(true)
  end
  
  if new_resource.admin_user
    #Admin node configure ability to log in to members.
    home = get_home(new_resource.admin_user)
    get_pubkey(home)
    new_resource.updated_by_last_action(true)
  end
  hosts = []
  members.each { |n|
    hosts.push n['name']    
  }
  node['dsh']['hosts'] = hosts
end


action :leave do
  execute "revoke access" do
    command "rm /tmp/#{new_resource.user}"
  end
end

def update_host_key()
  host_key = ::File.read("/etc/ssh/ssh_host_rsa_key.pub").strip
  if host_key != node["dsh"]["host_key"]
    Chef::Log.info("Updating host key to #{host_key}")
    node["dsh"]["host_key"] = host_key
    new_resource.updated_by_last_action(true)
  end
end

def find_dsh_group_members(name)
  return search(:node, "dsh_groups:#{new_resource.name}")
end

def find_dsh_group_admins(name)
  return search(:node, "dsh_admin_groups:#{new_resource.name}")
end

def get_home(user)
  ::File.expand_path "~#{user}"
end

def get_pubkey(home)
  privkey_path = "#{home}/.ssh/id_rsa"
  pubkey_path = "#{privkey_path}.pub"
  if not (::File.exists? privkey_path or ::File.exists? pubkey_path)
    Chef::Log.info("Generating ssh keys for user #{new_resource.admin_user}")
    system("su #{new_resource.admin_user} -c 'ssh-keygen -q -f #{privkey_path} -P \"\"'", :in=>"/dev/null")
    new_resource.updated_by_last_action(true)
  end
  pubkey = ::File.read("#{home}/.ssh/id_rsa.pub").strip
  node["dsh"]["admin_groups"][new_resource.name] ||= {}
  if pubkey != node["dsh"]["admin_groups"][new_resource.name]["pubkey"]
    Chef::Log.info("Updating pubkey for admin_user #{new_resource.admin_user}")
    node["dsh"]["admin_groups"][new_resource.name] = {
      "user" => new_resource.admin_user,
      "pubkey" => pubkey
    }
  end
end

if Chef::Config[:solo]
  Chef::Log.warn("This recipe uses search. Chef Solo does not support search.")
end
