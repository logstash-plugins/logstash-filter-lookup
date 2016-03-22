# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/lookup"
require "webmock/rspec"
require 'digest/sha1'
WebMock.disable_net_connect!(allow_localhost: true)

describe LogStash::Filters::LookUp do

  let(:config) { Hash.new }
  subject { described_class.new(config) }

  describe "webserver mapping" do
    config <<-CONFIG
      filter {
          lookup {
              field       => "status"
              destination => "mapping"
              url  => "http://dummyurl/"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/").
            with(:headers => {'Accept' => '*/*', 'User-Agent' => 'Ruby'}).
            to_return(:status => 200, :body => "\
                        '200': OK\n\
                        '300': Redirect\n\
                        '400': Client Error\n\
                        '500': Server Error", :headers => {})
      end
    end

    sample("status" => "200") do
      insist { subject["mapping"] } == "OK"
    end
  end

  describe "webserver mapping existing YML" do
    config <<-CONFIG
      filter {
          lookup {
              field       => "status"
              destination => "mapping"
              url  => "http://dummyurl/"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/").
            with(:headers => {'Accept' => '*/*', 'User-Agent' => 'Ruby'}).
            to_return(:status => 200, :body => "\
                        '200': OK\n\
                        '300': Redirect\n\
                        '400': Client Error\n\
                        '500': Server Error", :headers => {})
      end
    end

    sample("status" => "200") do
      insist { subject["mapping"] } == "OK"
    end
  end

  describe "webserver mapping not valid" do
    config <<-CONFIG
      filter {
          lookup {
              field       => "status"
              destination => "mapping"
              url  => "http://dummyurl/"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/").
            with(:headers => {'Accept' => '*/*', 'User-Agent' => 'Ruby'}).
            to_return(:status => 200, :body => "\
                        '200': OK\n\
                        '300': Redirect\n\
                        '400', Client Error\n\
                        '500': Server Error", :headers => {})
      end
    end

    sample("status" => "200") do
      insist { subject["mapping"] } == nil
    end
  end

  describe "webserver mapping JSON" do
    config <<-CONFIG
      filter {
          lookup {
              field       => "status"
              destination => "mapping"
              url  => "http://dummyurl/json"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/json").
            with(:headers => {'Accept' => '*/*', 'User-Agent' => 'Ruby'}).
            to_return(:status => 200, :body => '{
	"200": "OK",
	"300": "Redirect",
	"400": "Client Error",
	"500": "Server Error"
}', :headers => {})
      end
    end

    sample("status" => "200") do
      insist { subject["mapping"] } == "OK"
    end
  end

  describe "webserver mapping existing JSON" do
    config <<-CONFIG
      filter {
          lookup {
              field       => "status"
              destination => "mapping"
              url  => "http://dummyurl/json"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/json").
            with(:headers => {'Accept' => '*/*', 'User-Agent' => 'Ruby'}).
            to_return(:status => 200, :body => '{
	"200": "OK",
	"300": "Redirect",
	"400": "Client Error",
	"500": "Server Error"
}', :headers => {})
      end
    end

    sample("status" => "200") do
      insist { subject["mapping"] } == "OK"
    end
  end

  describe "webserver mapping not valid JSON" do
    config <<-CONFIG
      filter {
          lookup {
              field       => "status"
              destination => "mapping"
              url  => "http://dummyurl/json"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/json").
            with(:headers => {'Accept' => '*/*', 'User-Agent' => 'Ruby'}).
            to_return(:status => 200, :body => '{
	"200": "OK",
	"300": "Redirect",
	"400": "Client Error",
	"500", "Server Error"
}', :headers => {})
      end
    end

    sample("status" => "200") do
      insist { subject["mapping"] } == nil
    end
  end

  describe "webserver mapping CSV" do
    config <<-CONFIG
      filter {
          lookup {
              field       => "status"
              destination => "mapping"
              url  => "http://dummyurl/csv"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/csv").
            with(:headers => {'Accept' => '*/*', 'User-Agent' => 'Ruby'}).
            to_return(:status => 200, :body => "200,OK
300,Redirect
400,Client Error
500,Server Error
", :headers => {})
      end
    end

    sample("status" => "200") do
      insist { subject["mapping"] } == "OK"
    end
  end

  describe "webserver mapping existing CSV" do
    config <<-CONFIG
      filter {
          lookup {
              field       => "status"
              destination => "mapping"
              url  => "http://dummyurl/csv"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/csv").
            with(:headers => {'Accept' => '*/*', 'User-Agent' => 'Ruby'}).
            to_return(:status => 200, :body => "200,OK
300,Redirect
400,Client Error
500,Server Error
", :headers => {})
      end
    end

    sample("status" => "200") do
      insist { subject["mapping"] } == "OK"
    end
  end

  describe "webserver mapping not valid CSV" do
    config <<-CONFIG
      filter {
          lookup {
              field       => "status"
              destination => "mapping"
              url  => "http://dummyurl/csv"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/csv").
            with(:headers => {'Accept' => '*/*', 'User-Agent' => 'Ruby'}).
            to_return(:status => 200, :body => "200OK
300,Redirect
400,Client Error
500:Server Error
", :headers => {})
      end
    end

    sample("status" => "200") do
      insist { subject["mapping"] } == nil
    end
  end

  context "allow sprintf" do
    let(:config) do
      {
          "field" => "status",
          "destination" => "mapping",
          "fallback" => "%{missing_mapping}",
          "url" => "http://dummyurl/"
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
