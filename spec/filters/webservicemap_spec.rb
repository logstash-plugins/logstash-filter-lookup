# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/webservicemap"
require "webmock/rspec"
require 'digest/sha1'
WebMock.disable_net_connect!(allow_localhost: true)

describe LogStash::Filters::WebServiceMap do

  let(:config) { Hash.new }
  subject { described_class.new(config) }

  describe "webserver mapping" do
      config <<-CONFIG
      filter {
          webservicemap {
              field       => "status"
              destination => "mapping"
              map_url  => "http://dummyurl/"
          }
      }
      CONFIG

      RSpec.configure do |config|
          hash = Digest::SHA1.hexdigest 'http://dummyurl/'
          config.before(:each) do
              FileUtils.rm_rf(hash+'.yml')
              stub_request(:get, "http://dummyurl/").
              with(:headers => {'Accept'=>'*/*', 'User-Agent'=>'Ruby'}).
              to_return(:status => 200, :body => "\
                        '200': OK\n\
                        '300': Redirect\n\
                        '400': Client Error\n\
                        '500': Server Error", :headers => {})
          end
          config.after(:all) do
              FileUtils.rm_rf(hash+'.yml')
          end
      end

      sample("status" => "200") do
          insist { subject["mapping"] } == "OK"
      end
  end

  describe "webserver mapping existing YML" do
      config <<-CONFIG
      filter {
          webservicemap {
              field       => "status"
              destination => "mapping"
              map_url  => "http://dummyurl/"
          }
      }
      CONFIG

      RSpec.configure do |config|
        hash = Digest::SHA1.hexdigest 'http://dummyurl/'
          config.before(:each) do
              FileUtils.rm_rf(hash+'.yml')
              File.open(hash+'.yml', 'wb') { |f| f.write("\
                                                       '200': OKF\n\
                                                       '300': Redirect\n\
                                                       '400': Client Error\n\
                                                       '500': Server Error") }
              stub_request(:get, "http://dummyurl/").
              with(:headers => {'Accept'=>'*/*', 'User-Agent'=>'Ruby'}).
              to_return(:status => 200, :body => "\
                        '200': OK\n\
                        '300': Redirect\n\
                        '400': Client Error\n\
                        '500': Server Error", :headers => {})
          end
          config.after(:all) do
              FileUtils.rm_rf(hash+'.yml')
          end
      end

      sample("status" => "200") do
          insist { subject["mapping"] } == "OK"
      end
  end

  describe "webserver mapping not valid" do
      config <<-CONFIG
      filter {
          webservicemap {
              field       => "status"
              destination => "mapping"
              map_url  => "http://dummyurl/"
          }
      }
      CONFIG

      RSpec.configure do |config|
        hash = Digest::SHA1.hexdigest 'http://dummyurl/'
          config.before(:each) do
              FileUtils.rm_rf(hash+'.yml')
              stub_request(:get, "http://dummyurl/").
              with(:headers => {'Accept'=>'*/*', 'User-Agent'=>'Ruby'}).
              to_return(:status => 200, :body => "\
                        '200': OK\n\
                        '300': Redirect\n\
                        '400', Client Error\n\
                        '500': Server Error", :headers => {})
          end
          config.after(:all) do
              FileUtils.rm_rf(hash+'.yml')
          end
      end

      sample("status" => "200") do
          insist { subject["mapping"] } == nil
      end
  end
=begin
  describe "webserver mapping not valid existing YML" do
      config <<-CONFIG
      filter {
          webservicemap {
              field       => "status"
              destination => "mapping"
              map_url  => "http://dummyurl/"
          }
      }
      CONFIG
    context "init" do
      let(:my_map) { {"200"=>"OKF"}}
    end

      RSpec.configure do |config|

        hash = Digest::SHA1.hexdigest 'http://dummyurl/'
          config.before(:each) do
              stub_request(:get, "http://dummyurl/").
              with(:headers => {'Accept'=>'*/*', 'User-Agent'=>'Ruby'}).
              to_return(:status => 200, :body => "\
                        '200': OK\n\
                        '300': Redirect\n\
                        '400', Client Error\n\
                        '500': Server Error", :headers => {})
          end
          config.after(:all) do
              FileUtils.rm_rf(hash+'.yml')
          end
      end

      sample("status" => "200") do
          insist { subject["mapping"] } == "OKF"
      end
  end
=end
    context "allow sprintf" do
      let(:config) do
        {
          "field"       => "status",
          "destination" => "mapping",
          "fallback" => "%{missing_mapping}",
          "map_url"  => "http://dummyurl/"
        }
      end

      let(:event) { LogStash::Event.new("status" => "200", "missing_mapping" => "missing no match") }

      it "return the exact mapping" do
        subject.register
        subject.filter(event)
        expect(event["mapping"]).to eq("missing no match")
      end
    end
end
