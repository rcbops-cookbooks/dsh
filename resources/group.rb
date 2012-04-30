actions :join, :leave

def initialize(*args)
  super
  @action = :join
end

attribute :group, :kind_of => String, :name_attribute => true
attribute :user, :kind_of => String, :default => true
attribute :admin_user, :kind_of => String, :default => nil
attribute :admin_pubkey, :kind_of => String, :default => nil
attribute :network, :kind_of => String, :default => nil
