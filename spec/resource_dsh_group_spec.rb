require "spec_helper"

describe Chef::Resource::DshGroup do
  subject(:resource) { Chef::Resource::DshGroup.new("admin") }

  describe "#initialize" do
    its(:action) { should eq :join }
    its(:allowed_actions) { should eq [:execute, :join, :nothing] }
    its(:provider) { should eq Chef::Provider::DshGroup }
    its(:resource_name) { should eq :dsh_group }
  end

  describe "#group" do
    it "defaults to resource.name" do
      resource.group.should eq resource.name
    end

    it "accepts a String value" do
      resource.group("group").should eq "group"
    end

    it "rejects non String values" do
      expect { resource.group(true) }.to raise_error(Chef::Exceptions::ValidationFailed)
    end
  end

  describe "#user" do
    it "defaults to nil" do
      resource.user.should be_nil
    end

    it "accepts a String value" do
      resource.user("user").should eq "user"
    end

    it "accepts a Hash value" do
      resource.user(:username => "user").should == { :username => "user" }
    end

    it "rejects non String/Hash values" do
      expect { resource.user(true) }.to raise_error(Chef::Exceptions::ValidationFailed)
    end
  end

  describe "#admin_user" do
    it "defaults to nil" do
      resource.admin_user.should be_nil
    end

    it "accepts a String value" do
      resource.admin_user("admin_user").should eq "admin_user"
    end

    it "accepts a Hash value" do
      resource.admin_user(:admin_username => "admin_user").should == { :admin_username => "admin_user" }
    end

    it "rejects non String/Hash values" do
      expect { resource.admin_user(true) }.to raise_error(Chef::Exceptions::ValidationFailed)
    end
  end

  describe "#admin_pubkey" do
    it "defaults to nil" do
      resource.admin_pubkey.should be_nil
    end

    it "accepts a String value" do
      resource.admin_pubkey("admin_pubkey").should eq "admin_pubkey"
    end

    it "rejects non String value" do
      expect { resource.admin_pubkey(true) }.to raise_error(Chef::Exceptions::ValidationFailed)
    end
  end

  describe "#network" do
    it "defaults to nil" do
      resource.network.should be_nil
    end

    it "accepts a String value" do
      resource.network("network").should eq "network"
    end

    it "rejects non String value" do
      expect { resource.network(true) }.to raise_error(Chef::Exceptions::ValidationFailed)
    end
  end

  describe "#execute" do
    it "defaults to nil" do
      resource.execute.should be_nil
    end

    it "accepts a String value" do
      resource.execute("execute").should eq "execute"
    end

    it "rejects non String value" do
      expect { resource.execute(true) }.to raise_error(Chef::Exceptions::ValidationFailed)
    end
  end

  describe "#skip_create" do
    it "defaults with root/nova/glance user names" do
      resource.skip_create.should eq ["root", "nova", "glance"]
    end

    it "accepts an Array" do
      resource.skip_create(["foop"]).should eq ["foop"]
    end

    it "rejects non Array values" do
      expect { resource.skip_create(true) }.to raise_error(Chef::Exceptions::ValidationFailed)
    end
  end
end
