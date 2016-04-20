# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/lookup"
require "webmock/rspec"
WebMock.disable_net_connect!(allow_localhost: true)

describe LogStash::Filters::LookUp do

  let(:config) { Hash.new }
  subject { described_class.new(config) }

  describe "file mapping" do
    config <<-CONFIG
      filter {
          lookup {
              fields       => ["status"]
              type => "file"
              path  => "filename"
          }
      }
    CONFIG
    content = "\
                        '200': OK\n\
                        '300': Redirect\n\
                        '400': Client Error\n\
                        '500': Server Error"
    filename = 'filename'

    RSpec.configure do |config|
      config.before(:each) do
        allow(File).to receive(:open).with(filename, 'r').and_yield( StringIO.new(content) )
      end
    end
    sample({"status" => "200"}) do
      insist { subject["lookup_result"]["status"] } == "OK"
    end
  end

  describe "webserver mapping" do
    config <<-CONFIG
      filter {
          lookup {
              fields       => ["status"]
              format => "yml"
              url  => "http://dummyurl/"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:any, "http://dummyurl/").
            to_return(:status => 200, :body => "\
                        '200': OK\n\
                        '300': Redirect\n\
                        '400': Client Error\n\
                        '500': Server Error", :headers => {})
      end
    end

    sample({"status" => "200"}) do
      insist { subject["lookup_result"]["status"] } == "OK"
    end
  end

  describe "webserver mapping existing YML" do
    config <<-CONFIG
      filter {
          lookup {
              fields       => ["status"]
              format => "yml"
              url  => "http://dummyurl/"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/").
            to_return(:status => 200, :body => "\
                        '200': OK\n\
                        '300': Redirect\n\
                        '400': Client Error\n\
                        '500': Server Error", :headers => {})
      end
    end

    sample({"status" => "200"}) do
      insist { subject["lookup_result"]["status"] } == "OK"
    end
  end

  describe "webserver mapping not valid on register" do
    config <<-CONFIG
      filter {
          lookup {
              fields       => ["status"]
              format => "yml"
              url  => "http://dummyurl/"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/").
            to_return(:status => 200, :body => "\
                        '200': OK\n\
                        '300': Redirect\n\
                        '400', Client Error\n\
                        '500': Server Error", :headers => {})
      end
    end

    sample({"status" => "200"}) do
      expect { subject }.to raise_error
    end
  end

  describe "webserver mapping JSON" do
    config <<-CONFIG
      filter {
          lookup {
              fields       => ["status"]
              format => "json"
              url  => "http://dummyurl/json"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/json").
            to_return(:status => 200, :body => '{
	"200": "OK",
	"300": "Redirect",
	"400": "Client Error",
	"500": "Server Error"
}', :headers => {})
      end
    end

    sample({"status" => "200"}) do
      insist { subject["lookup_result"]["status"] } == "OK"
    end
  end

  describe "webserver mapping existing JSON" do
    config <<-CONFIG
      filter {
          lookup {
              fields       => ["status"]
              format => "json"
              url  => "http://dummyurl/json"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/json").
            to_return(:status => 200, :body => '{
	"200": "OK",
	"300": "Redirect",
	"400": "Client Error",
	"500": "Server Error"
}', :headers => {})
      end
    end

    sample({"status" => "200"}) do
      insist { subject["lookup_result"]["status"] } == "OK"
    end
  end

  describe "webserver mapping not valid JSON on register" do
    config <<-CONFIG
      filter {
          lookup {
              fields       => ["status"]
              format => "json"
              url  => "http://dummyurl/json"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/json").
            to_return(:status => 200, :body => '{
	"200": "OK",
	"300": "Redirect",
	"400": "Client Error",
	"500", "Server Error"
}', :headers => {})
      end
    end

    sample({"status" => "200"}) do
      expect { subject }.to raise_error
    end
  end

  describe "webserver mapping CSV" do
    config <<-CONFIG
      filter {
          lookup {
              fields       => ["status"]
              format => "csv"
              url  => "http://dummyurl/csv"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/csv").
            to_return(:status => 200, :body => "200,OK
300,Redirect
400,Client Error
500,Server Error
", :headers => {})
      end
    end

    sample({"status" => "200"}) do
      insist { subject["lookup_result"]["status"] } == "OK"
    end
  end

  describe "webserver mapping existing CSV" do
    config <<-CONFIG
      filter {
          lookup {
              fields       => ["status"]
              format => "csv"
              url  => "http://dummyurl/csv"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/csv").
            to_return(:status => 200, :body => "200,OK
300,Redirect
400,Client Error
500,Server Error
", :headers => {})
      end
    end

    sample({"status" => "200"}) do
      insist { subject["lookup_result"]["status"] } == "OK"
    end
  end

  describe "webserver mapping not valid CSV" do
    config <<-CONFIG
      filter {
          lookup {
              fields       => ["status"]
              format => "csv"
              url  => "http://dummyurl/csv"
          }
      }
    CONFIG

    RSpec.configure do |config|
      config.before(:each) do
        stub_request(:get, "http://dummyurl/csv").
            to_return(:status => 200, :body => "200OK
300,Redirect
400,Client Error
500:Server Error
", :headers => {})
      end
    end

    sample({"status" => "200"}) do
      insist { subject["lookup_result"]["status"] } == nil
    end
  end

  context "allow sprintf" do
    let(:config) do
      {
          "fields" => ["status"],
          "default_values" => {"status"=>"%{missing_mapping}"},
          "type" => "file",
          "path"=>"filename"
      }
    end
    content = "\
                        '200': OK\n\
                        '300': Redirect\n\
                        '400': Client Error\n\
                        '500': Server Error"
    filename = 'filename'
    RSpec.configure do |config|
      config.before(:each) do
        allow(File).to receive(:open).with(filename, 'r').and_yield( StringIO.new(content) )
      end
    end
    let(:event) { LogStash::Event.new("status" => "250", "missing_mapping" => "missing no match") }

    it "return the exact mapping" do
      subject.register
      subject.filter(event)
      expect(event["lookup_result"]["status"]).to eq("missing no match")
    end
  end
end
