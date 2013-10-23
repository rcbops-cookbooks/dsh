require "spec_helper"
require "chef/run_context"
require "chef/provider/user"
require "chef/provider/directory"
require "chef/provider/file"
require "chef/application"

describe Chef::Provider::DshGroup do
  subject(:provider) do
    provider = Chef::Provider::DshGroup.new(resource, context)
    provider.load_current_resource
    provider
  end
  let(:resource) { Chef::Resource::DshGroup.new(group) }
  let(:context) { double(Chef::RunContext).as_null_object }
  let(:node) { provider.node }
  let(:file_provider) { double(Chef::Provider::File) }
  let(:user_provider) { double(Chef::Provider::User) }
  let(:directory_provider) { double(Chef::Provider::Directory) }
  let(:fqdn) { "localhost.localdomain" }
  let(:group) { "testing" }
  let(:user) { "user" }
  let(:admin_user) { "admin" }

  before do
    provider.stub("node").and_return(Chef::Node.new)
  end

  describe "#load_current_resource" do
    it "copies new resource to current resource" do
      current_resource = provider.current_resource
      [:group, :user, :admin_user, :admin_pubkey, :network, :execute, :skip_create].each do |attr|
        current_resource.send(attr).should eq resource.send(attr)
      end
    end
  end

  describe "#install_packages" do
    it "installs platform packages" do
      node.set["pssh"]["platform"]["pssh_packages"] = ["farp"]
      node.set["pssh"]["platform"]["package_options"] = "-f"

      # packages provider should install packages with options
      provider.stub_chain("resource_collection", "find").and_raise(Chef::Exceptions::ResourceNotFound)

      provider.should_receive("package").with("farp").and_yield do |block|
        block.should_receive("action").with(:install)
        block.should_receive("options").with("-f")
      end

      provider.install_packages
    end
  end

  describe "#create_users" do
    it "creates users" do
      # specify user/admin_user
      resource.user(user)
      resource.admin_user(admin_user)

      # the chef providers should receive create calls
      file_provider.should_receive("run_action").exactly(4).times.with(:create)
      user_provider.should_receive("run_action").exactly(2).times.with(:create)
      directory_provider.should_receive("run_action").exactly(4).times.with(:create)
      provider.stub_chain("resource_collection", "find").and_raise(Chef::Exceptions::ResourceNotFound)


      [user, admin_user].each do |username|
        provider.should_receive("get_user_home").with(username).and_return("/home/#{username}")

        # creates user
        provider.should_receive("user").with(username).and_return(user_provider)
        user_provider.should_receive("instance_exec").and_yield do |block|
          block.should_receive("shell").with("/bin/bash")
          block.should_receive("home").with("/home/#{username}")
        end.and_return(user_provider)

        # creates user directory
        provider.should_receive("directory").with("/home/#{username}").and_return(directory_provider)
        directory_provider.should_receive("instance_exec").and_yield do |block|
          block.should_receive("owner").with(username)
          block.should_receive("group").with(username)
          block.should_receive("mode").with(0700)
        end.and_return(directory_provider)

        # creates user .ssh directory
        provider.should_receive("directory").with("/home/#{username}/.ssh").and_return(directory_provider)
        directory_provider.should_receive("instance_exec").and_yield do |block|
          block.should_receive("owner").with(username)
          block.should_receive("group").with(username)
        end.and_return(directory_provider)

        # creates .ssh files
        ["authorized_keys", "known_hosts"].each do |filename|
          provider.should_receive("file").with("/home/#{username}/.ssh/#{filename}").and_return(file_provider)
          file_provider.should_receive("instance_exec").and_yield do |block|
            block.should_receive("owner").with(username)
            block.should_receive("group").with(username)
          end.and_return(file_provider)
        end
      end

      provider.create_users
    end

    context "with user hashes" do
      it "creates users" do
        # specify user/admin_user
        resource.user(:username => user, :uid => 500)
        resource.admin_user(:username => admin_user, :uid => 500)

        # the chef providers should receive create calls
        file_provider.should_receive("run_action").exactly(4).times.with(:create)
        user_provider.should_receive("run_action").exactly(2).times.with(:create)
        directory_provider.should_receive("run_action").exactly(4).times.with(:create)
        provider.stub_chain("resource_collection", "find").and_raise(Chef::Exceptions::ResourceNotFound)


        [user, admin_user].each do |username|
          provider.should_receive("get_user_home").with(username).and_return("/home/#{username}")

          # creates user
          provider.should_receive("user").with(username).and_return(user_provider)
          user_provider.should_receive("instance_exec").and_yield do |block|
            block.should_receive("shell").with("/bin/bash")
            block.should_receive("home").with("/home/#{username}")
          end.and_return(user_provider)
          user_provider.should_receive("uid").with(500)

          # creates user directory
          provider.should_receive("directory").with("/home/#{username}").and_return(directory_provider)
          directory_provider.should_receive("instance_exec").and_yield do |block|
            block.should_receive("owner").with(username)
            block.should_receive("group").with(username)
            block.should_receive("mode").with(0700)
          end.and_return(directory_provider)

          # creates user .ssh directory
          provider.should_receive("directory").with("/home/#{username}/.ssh").and_return(directory_provider)
          directory_provider.should_receive("instance_exec").and_yield do |block|
            block.should_receive("owner").with(username)
            block.should_receive("group").with(username)
          end.and_return(directory_provider)

          # creates .ssh files
          ["authorized_keys", "known_hosts"].each do |filename|
            provider.should_receive("file").with("/home/#{username}/.ssh/#{filename}").and_return(file_provider)
            file_provider.should_receive("instance_exec").and_yield do |block|
              block.should_receive("owner").with(username)
              block.should_receive("group").with(username)
            end.and_return(file_provider)
          end
        end

        provider.create_users
      end
    end

    context "with skip_create users" do
      it "skips the specified users in create" do
        # specify user/admin_user
        resource.user("nova")
        resource.admin_user("root")

        # the chef providers should receive create calls
        file_provider.should_receive("run_action").exactly(4).times.with(:create)
        directory_provider.should_receive("run_action").exactly(2).times.with(:create)
        provider.stub_chain("resource_collection", "find").and_raise(Chef::Exceptions::ResourceNotFound)


        [resource.user, resource.admin_user].each do |username|
          provider.should_receive("get_user_home").with(username).and_return("/home/#{username}")

          # does not create  user
          provider.should_not_receive("user").with(username)

          # does not create user directory
          provider.should_not_receive("directory").with("/home/#{username}")

          # creates user .ssh directory
          provider.should_receive("directory").with("/home/#{username}/.ssh").and_return(directory_provider)
          directory_provider.should_receive("instance_exec").and_yield do |block|
            block.should_receive("owner").with(username)
            block.should_receive("group").with(username)
          end.and_return(directory_provider)

          # creates .ssh files
          ["authorized_keys", "known_hosts"].each do |filename|
            provider.should_receive("file").with("/home/#{username}/.ssh/#{filename}").and_return(file_provider)
            file_provider.should_receive("instance_exec").and_yield do |block|
              block.should_receive("owner").with(username)
              block.should_receive("group").with(username)
            end.and_return(file_provider)
          end
        end

        provider.create_users
      end
    end
  end

  describe "#update_host_key_attribute" do
    it "updates the host key attribute from the ssh file" do
      # return host rsa file content
      File.should_receive("read").with("/etc/ssh/ssh_host_rsa_key.pub").and_return("host_key_contents  \n")

      resource.should_receive("updated_by_last_action").with(true)
      provider.update_host_key_attribute

      node["dsh"]["host_key"].should eq "host_key_contents"
    end
  end

  describe "#configure_user_attribute" do
    it "adds the user to the group attributes" do
      # specify the user
      resource.user(user)

      provider.configure_user_attribute

      # ensure the user was added
      node["dsh"]["groups"][group]["user"].should eq user
    end
  end

  describe "#configure_access_name_attribute" do
    context "with network" do
      it "adds the access_name from network name lookup" do
        # configure ipmanagement to return an ip for a network
        ipmanagement = double("Chef::Recipe::IPManagement")
        ipmanagement.should_receive("get_ip_for_net").with("management", node).and_return("localhost")
        stub_const("Chef::Recipe::IPManagement", ipmanagement)

        # specify the network/user
        resource.network("management")
        resource.user(user)

        provider.configure_access_name_attribute

        # ensure access name was set from ipmanagement results
        node["dsh"]["groups"][group]["access_name"].should eq "localhost"
      end
    end

    context "without network" do
      it "adds the access_name from fqdn" do
        # specify the user and fqdn
        node.set["fqdn"] = fqdn
        resource.user(user)

        provider.configure_access_name_attribute

        # ensure access name was set from fqdn attribute
        node["dsh"]["groups"][group]["access_name"].should eq fqdn
      end
    end
  end

  describe "#configure_admin_user_attribute" do
    it "adds the admin_user to the group attributes" do
      # specify the user
      resource.admin_user(admin_user)

      provider.configure_admin_user_attribute

      # ensure the admin user was set
      node["dsh"]["admin_groups"][group]["admin_user"].should eq admin_user
    end
  end

  describe "#configure_pubkey_attribute" do
    context "if admin user hash pub/priv keys don't exist" do
      it "creates a new keypair and configures the pubkey attribute" do
        # specify the admin_user/pubkey
        resource.admin_user(:username => admin_user, :uid => 500)
        node.set["dsh"]["admin_groups"][group]["pubkey"] = nil

        # return exists/content from the priv/pub files
        provider.should_receive("get_user_home").with(admin_user).and_return("/nonexists")
        File.should_receive("exists?").with("/nonexists/.ssh/id_rsa").and_return(false)
        File.should_receive("exists?").with("/nonexists/.ssh/id_rsa.pub").and_return(false)
        File.should_receive("read").with("/nonexists/.ssh/id_rsa.pub").and_return("pubkey")

        # we should be creating a new keypair
        cmd = "su #{admin_user} -c 'ssh-keygen -q -f /nonexists/.ssh/id_rsa -P \"\"'"
        provider.should_receive("system").with(cmd, :in => "/dev/null")

        provider.configure_pubkey_attribute

        # ensure the pubkey is set from the pub file
        node["dsh"]["admin_groups"][group]["pubkey"].should eq "pubkey"
      end
    end

    context "if admin user pub/priv keys don't exist" do
      it "creates a new keypair and configures the pubkey attribute" do
        # specify the admin_user/pubkey
        resource.admin_user(admin_user)
        node.set["dsh"]["admin_groups"][group]["pubkey"] = nil

        # return exists/content from the priv/pub files
        provider.should_receive("get_user_home").with(admin_user).and_return("/nonexists")
        File.should_receive("exists?").with("/nonexists/.ssh/id_rsa").and_return(false)
        File.should_receive("exists?").with("/nonexists/.ssh/id_rsa.pub").and_return(false)
        File.should_receive("read").with("/nonexists/.ssh/id_rsa.pub").and_return("pubkey")

        # we should be creating a new keypair
        cmd = "su #{admin_user} -c 'ssh-keygen -q -f /nonexists/.ssh/id_rsa -P \"\"'"
        provider.should_receive("system").with(cmd, :in => "/dev/null")

        provider.configure_pubkey_attribute

        # ensure the pubkey is set from the pub file
        node["dsh"]["admin_groups"][group]["pubkey"].should eq "pubkey"
      end
    end

    context "if admin user priv keys exists and private doesn't" do
      it "creates a new pubkey and configures the pubkey attribute" do
        # specify admin_user/pubkey
        resource.admin_user(admin_user)
        node.set["dsh"]["admin_groups"][group]["pubkey"] = nil

        # return exists/content from the priv/pub keys files
        provider.should_receive("get_user_home").and_return("/nonexists")
        File.should_receive("exists?").with("/nonexists/.ssh/id_rsa").and_return(true)
        File.should_receive("exists?").with("/nonexists/.ssh/id_rsa.pub").and_return(false)
        File.should_receive("read").with("/nonexists/.ssh/id_rsa.pub").and_return("pubkey")

        # we should be generating a pub key from the priv key
        cmd = "su #{admin_user} -c 'ssh-keygen -y -f /nonexists/.ssh/id_rsa > /nonexists/.ssh/id_rsa.pub'"
        provider.should_receive("system").with(cmd)

        provider.configure_pubkey_attribute

        # ensure the pubkey is loaded from the pub file
        node["dsh"]["admin_groups"][group]["pubkey"].should eq "pubkey"
      end
    end

    context "it admin user priv key exists without pub key" do
      it "throws a fatal exception and halts" do
        # specify the admin_user
        resource.admin_user(admin_user)

        # make the priv key files not exist
        provider.should_receive("get_user_home").and_return("/nonexists")
        File.should_receive("exists?").with("/nonexists/.ssh/id_rsa").and_return(false)
        File.should_receive("exists?").with("/nonexists/.ssh/id_rsa.pub").and_return(true)

        # ensure we toss up an error because we have no priv key
        Chef::Application.should_receive("fatal!").with(/private key is missing/)
        expect { provider.configure_pubkey_attribute }.to raise_error
      end
    end
  end

  describe "#add_admin_nodes_to_authorized_keys" do
    # TODO: Add more tests around stale keys/node vs file, etc
    context "when the file resource exists" do
      it "adds admin nodes to users authorized_keys" do
        # specify user/authorzed_keys
        resource.user(user)
        node.set["dsh"]["groups"][group]["authorized_keys"] = []

        # configure search results
        result = Chef::Node.new
        result.set["dsh"]["admin_groups"][group]["pubkey"] = "pubkey"

        # pretend resource doesn't exist
        provider.stub_chain("resource_collection", "find").
          with(:file => "/home/#{user}/.ssh/authorized_keys").
          and_return(file_provider)

        # chef provider should receive create call
        file_provider.should_receive("run_action").with(:create)

        # return search results
        provider.should_receive("find_dsh_group_admins").and_return([result])
        file_provider.should_receive("instance_exec").and_yield do |block|
          block.should_receive("owner").with(user)
          block.should_receive("group").with(user)
          block.should_receive("content").with("pubkey")
        end.and_return(file_provider)

        # read users current keys file for appending of admin keys
        provider.should_receive("get_user_home").with(user).and_return("/home/#{user}")
        File.should_receive("read").with("/home/#{user}/.ssh/authorized_keys").and_return("")

        provider.add_admin_nodes_to_authorized_keys

        # ensure authorized_keys is updated from the admins pubkey attribute
        node["dsh"]["groups"][group]["authorized_keys"].should eq ["pubkey"]
      end
    end

    context "when the file resource does not exist" do
      it "adds admin nodes to users authorized_keys" do
        # specify user/authorzed_keys
        resource.user(user)
        node.set["dsh"]["groups"][group]["authorized_keys"] = []

        # configure search results
        result = Chef::Node.new
        result.set["dsh"]["admin_groups"][group]["pubkey"] = "pubkey"

        # pretend resource doesn't exist
        provider.stub_chain("resource_collection", "find").and_raise(Chef::Exceptions::ResourceNotFound)

        # chef provider should receive create call
        file_provider.should_receive("run_action").with(:create)

        # return search results
        provider.should_receive("find_dsh_group_admins").and_return([result])
        provider.should_receive("file").with("/home/#{user}/.ssh/authorized_keys").and_return(file_provider)
        file_provider.should_receive("instance_exec").and_yield do |block|
          block.should_receive("owner").with(user)
          block.should_receive("group").with(user)
          block.should_receive("content").with("pubkey")
        end.and_return(file_provider)

        # read users current keys file for appending of admin keys
        provider.should_receive("get_user_home").with(user).and_return("/home/#{user}")
        File.should_receive("read").with("/home/#{user}/.ssh/authorized_keys").and_return("")

        provider.add_admin_nodes_to_authorized_keys

        # ensure authorized_keys is updated from the admins pubkey attribute
        node["dsh"]["groups"][group]["authorized_keys"].should eq ["pubkey"]
      end
    end
  end

  describe "#create_dsh_directories" do
    it "creates dsh directories for admin user" do
      # specify admin user
      resource.admin_user(admin_user)

      # create dsh group directories
      directory_provider.should_receive("run_action").exactly(2).times.with(:create)
      provider.should_receive("get_user_home").with(admin_user).and_return("/home/#{admin_user}")
      provider.stub_chain("resource_collection", "find").and_raise(Chef::Exceptions::ResourceNotFound)

      [".dsh", ".dsh/group"].each do |dir|
        provider.should_receive("directory").with("/home/#{admin_user}/#{dir}").and_return(directory_provider)
        directory_provider.should_receive("instance_exec").and_yield do |block|
          block.should_receive("owner").with(admin_user)
          block.should_receive("group").with(admin_user)
        end.and_return(directory_provider)
      end

      provider.create_dsh_directories
    end
  end

  describe "#add_member_nodes_to_known_hosts" do
    it "adds member nodes to admin users known_hosts" do
      # specify admin user
      resource.admin_user(admin_user)

      # mock user home
      provider.should_receive("get_user_home").exactly(2).times.with(admin_user).and_return("/home/#{admin_user}")

      # stub out su known hosts check
      provider.should_receive("known_hosts_contains?").with(admin_user, "localhost").and_return(true)

      # mock up know_hosts file access
      file = double(File)
      file.should_receive("path").and_return("/home/#{admin_user}/.ssh/known_hosts")
      file.should_receive("write").with("localhost hostkey\n")
      file.should_receive("close")
      File.should_receive("new").with("/home/#{admin_user}/.ssh/known_hosts", "a").and_return(file)

      # configure/return search results
      result = Chef::Node.new
      result.set["dsh"]["groups"][group]["user"] = user
      result.set["dsh"]["groups"][group]["access_name"] = "localhost"
      result.set["dsh"]["host_key"] = "hostkey"
      provider.should_receive("find_dsh_group_members").and_return([result])

      # create dsh group file
      file_provider.should_receive("run_action").with(:create)
      provider.should_receive("file").with("/home/#{admin_user}/.dsh/group/#{group}").and_yield do |block|
        block.should_receive("owner").with(admin_user)
        block.should_receive("group").with(admin_user)
        block.stub("new_resource").and_return(provider.new_resource)
        block.should_receive("content").with("#{user}@localhost\n")
      end.and_return(file_provider)

      provider.add_member_nodes_to_known_hosts

      # ensure dsh hosts contains the acces_name/pubkey information
      node["dsh"]["hosts"].should eq [{ "name" => "localhost", "key" => "hostkey" }]
    end
  end

  describe "#find_dsh_group_admins" do
    it "adds self to results if it has the admin group attribute" do
      # configure node to be in admin group
      node.stub("name").and_return("self")
      node.set["dsh"]["admin_groups"][group] = []

      # configure/return results
      result = Chef::Node.new
      result.stub("name").and_return("result")
      provider.should_receive("search").and_return([result])

      # ensure get get the result and self
      provider.find_dsh_group_admins.should eq [result, node]
    end
  end

  describe "#find_dsh_group_members" do
    it "adds self to results if it has the group attribute" do
      # configure node to be in admin group
      node.stub("name").and_return("self")
      node.set["dsh"]["groups"][group] = []

      # configure/return results
      result = Chef::Node.new
      result.stub("name").and_return("result")
      provider.should_receive("search").and_return([result])

      # ensure get get the result and self
      provider.find_dsh_group_members.should eq [result, node]
    end
  end

  describe "#get_user_name" do
    context "with a string" do
      it "returns the string" do
        provider.get_user_name("foop").should eq "foop"
      end
    end

    context "with a hash" do
      it "returns the username attribute over name attribute" do
        provider.get_user_name(:username => "foop", :name => "derp").should eq "foop"
        provider.get_user_name("username" => "foop", "name" => "derp").should eq "foop"
      end

      it "returns the name attribute" do
        provider.get_user_name(:name => "foop").should eq "foop"
        provider.get_user_name("name" => "foop").should eq "foop"
      end
    end
  end

  describe "#get_user_options" do
    context "with a hash" do
      it "returns the hash" do
        provider.get_user_options(:option => 1).should == { :option => 1 }
      end
    end

    context "with a Chef::Attribute" do
      it "returns the hash" do
        node.set["user"] = { "option" => "1" }

        provider.get_user_options(node["user"]).should == { "option" => "1" }
      end
    end
  end

  describe "#action_execute" do
    before do
      node.set["dsh"]["admin_groups"][group]["admin_user"] = "root"
      resource.execute('pwd')
    end

    context "under debian platform family" do
      it "executes the command in parallel ssh" do
        node.set["platform_family"] = "debian"

        cmd = /parallel-ssh -h .*\.dsh\/group\/testing -p 32 -t 120 'pwd'/

        provider.should_receive("execute").with(cmd).and_yield do |execute|
          execute.should_receive("user").with("root")
          execute.should_receive("only_if").with(/\.dsh\/group\/testing/)
        end

        provider.action_execute
      end
    end

    context "under rhel platform family" do
      it "executes the command in pdsh" do
        node.set["platform_family"] = "rhel"

        cmd = /pdsh -g testing 'pwd'/

        provider.should_receive("execute").with(cmd).and_yield do |execute|
          execute.should_receive("user").with("root")
          execute.should_receive("only_if").with(/\.dsh\/group\/testing/)
        end

        provider.action_execute
      end
    end
  end
end
