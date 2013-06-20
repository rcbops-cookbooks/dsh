require "spec_helper"

describe "dsh::default" do
  let(:chef_run) { runner.converge "dsh_test::default" }
  let(:node) { runner.node }
  let(:platform) { { :platform => "ubuntu", :version => "12.04" } }
  let(:results) { [] }
  let(:runner) { ChefSpec::ChefRunner.new(runner_options) }
  let(:runner_options) do
    {
      :cookbook_path => [COOKBOOK_PATH],
      :evaluate_guards => true,
      :step_into => step_into
    }.merge(platform)
  end
  let(:step_into) { ["dsh_group"] }

  describe ":join" do
    let(:chef_run) { runner.converge "dsh_test::group_provider_join" }
    let(:user_home) do
      dir = Dir.mktmpdir("user")
      ssh = Dir.mkdir(File.join(dir, ".ssh"))
      dsh = Dir.mkdir(File.join(dir, ".dsh"))
      dsh = Dir.mkdir(File.join(dir, ".dsh", "group"))
      File.write(File.join(dir, ".ssh", "authorized_keys"), "")
      File.write(File.join(dir, ".ssh", "id_rsa"), "userprivkey")
      File.write(File.join(dir, ".ssh", "id_rsa.pub"), "userpubkey")
      dir
    end
    let(:admin_user_home) do
      dir = Dir.mktmpdir("admin_user")
      ssh = Dir.mkdir(File.join(dir, ".ssh"))
      dsh = Dir.mkdir(File.join(dir, ".dsh"))
      dsh = Dir.mkdir(File.join(dir, ".dsh", "group"))
      File.write(File.join(dir, ".ssh", "authorized_keys"), "")
      File.write(File.join(dir, ".ssh", "id_rsa"), "adminuserprivkey")
      File.write(File.join(dir, ".ssh", "id_rsa.pub"), "adminuserpubkey")
      dir
    end
    let(:group_results) { [] }
    let(:admin_group_results) { [] }

    before do
      ::File.stub("expand_path").with(any_args).and_call_original
      ::File.stub("expand_path").with("~test").and_return(user_home)
      ::File.stub("expand_path").with("~admin").and_return(admin_user_home)


      ::File.stub("read").with(any_args).and_call_original
      ::File.stub("read").with("/etc/ssh/ssh_host_rsa_key.pub").and_return("hostpubkey")

      Chef::Provider::LWRPBase.any_instance.
        stub(:search).
        with(:node, "dsh_groups:testing AND chef_environment:#{node.chef_environment}").
        and_return(group_results)

      Chef::Provider::LWRPBase.any_instance.
        stub(:search).
        with(:node, "dsh_admin_groups:testing AND chef_environment:#{node.chef_environment}").
        and_return(admin_group_results)

      node.should_receive("save")
    end

    it "installs platform packages" do
      node.set["pssh"]["platform"]["pssh_packages"] = ["farp"]

      chef_run.should install_package("farp")
    end

    it "creates users" do
      chef_run.should create_user("test")
      chef_run.should create_user("admin")
    end

    it "creates users home directories" do
      chef_run.should create_directory(user_home)
      chef_run.should create_directory(admin_user_home)
    end

    it "creates users .ssh directories" do
      chef_run.should create_directory("#{user_home}/.ssh")
      chef_run.should create_directory("#{admin_user_home}/.ssh")
    end

    it "creates users ssh authorized keys/known_hosts" do
      chef_run.should create_file("#{user_home}/.ssh/authorized_keys")
      chef_run.should create_file("#{user_home}/.ssh/known_hosts")
    end

    it "creates admin users .dsh group directories" do
      chef_run.should_not create_directory("#{user_home}/.dsh/group")
      chef_run.should create_directory("#{admin_user_home}/.dsh/group")
    end

    it "create admin users dsh group file" do
      chef_run.should create_file("#{admin_user_home}/.dsh/group/testing")
    end

    it "updates node dsh/host_key attribute" do
      chef_run.node["dsh"]["host_key"].should eq "hostpubkey"
    end

    it "updates dsh group attributes" do
      chef_run.node.set["dsh"]["groups"]["testing"]["user"].should eq "test"
      chef_run.node.set["dsh"]["groups"]["testing"]["access_name"] = "127.0.0.1"
    end

    it "adds group admins search results to users authorized_keys" do
      admin_node = Chef::Node.new
      admin_node.set["name"] = "admin1"
      admin_node.set["dsh"]["admin_groups"]["testing"]["pubkey"] = "admingrouppubkey"
      admin_node.set["dsh"]["groups"]["testing"]["authorized_keys"] = "oldauthkey"
      admin_group_results << admin_node

      keys = "#{user_home}/.ssh/authorized_keys"
      ::File.stub("read").with(keys).and_return("userauthkeys")

      chef_run.should create_file(keys)
      chef_run.should create_file_with_content(keys, "userauthkeys\nadmingrouppubkey")
      chef_run.node["dsh"]["groups"]["testing"]["authorized_keys"].should eq ["admingrouppubkey"]
    end

    it "adds member hosts to admin user known_hosts" do
      member_node = Chef::Node.new
      member_node.set["name"] = "member1"
      member_node.set["dsh"]["groups"]["testing"]["user"] = "memberuser"
      member_node.set["dsh"]["groups"]["testing"]["access_name"] = "memberhost"
      member_node.set["dsh"]["host_key"] = "memberhostkey"
      group_results << member_node

      Chef::Provider::LWRPBase.any_instance.
        stub(:`).
        with("su admin -c 'ssh-keygen -F memberhost' | wc -l").
        and_return("0")

      chef_run.node["dsh"]["admin_groups"]["testing"]["admin_user"].should eq "admin"
      chef_run.node["dsh"]["hosts"].should eq [{ "name"=>"memberhost", "key"=>"memberhostkey" }]

      File.read("#{admin_user_home}/.ssh/known_hosts").should eq "memberhost memberhostkey\n"
      File.read("#{admin_user_home}/.dsh/group/testing").should eq "memberuser@memberhost\n"
    end
  end

  describe ":execute" do
    let(:chef_run) { runner.converge "dsh_test::group_provider_execute" }
    let(:admin_user_home) do
      dir = Dir.mktmpdir("admin_user")
      ssh = Dir.mkdir(File.join(dir, ".ssh"))
      dsh = Dir.mkdir(File.join(dir, ".dsh"))
      dsh = Dir.mkdir(File.join(dir, ".dsh", "group"))
      File.write(File.join(dir, ".ssh", "authorized_keys"), "")
      File.write(File.join(dir, ".ssh", "id_rsa"), "adminuserprivkey")
      File.write(File.join(dir, ".ssh", "id_rsa.pub"), "adminuserpubkey")
      dir
    end

    before do
      ::File.stub("expand_path").with(any_args).and_call_original
      ::File.stub("expand_path").with("~admin").and_return(admin_user_home)

      node.set["dsh"]["admin_groups"]["testing"]["admin_user"] = "admin"
    end

    it "execute the command in parallel ssh" do
      chef_run.should be_true
    end
  end
end
