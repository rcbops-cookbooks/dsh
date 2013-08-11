$: << File.expand_path(File.dirname(__FILE__) + "../../")
$: << File.expand_path(File.dirname(__FILE__) + "../../libraries")

if ENV["COVERAGE"]
  require "simplecov"

  SimpleCov.start do
    add_filter "spec"
  end
end

RSpec.configure do |c|
  c.filter_run :focus => true
  c.run_all_when_everything_filtered = true
end
