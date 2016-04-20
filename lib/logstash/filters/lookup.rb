# encoding: utf-8
require 'logstash/filters/base'
require 'logstash/namespace'
require 'json'
require 'csv'
require 'rest_client'


# A general search and replace tool which uses a Web service with a YAML, CSV or JSON response to determine replacement values.
#
# The map entries can be specified with a Web service who your request produces a YML, CSV or JSON response.
#
# Operationally, if the event field specified in the `field` configuration
# matches the EXACT contents of a map entry key, the field's value will be substituted
# with the matched key's value from the map.
#
# The lookup filter will put the contents of the maching event fields into field result.

class LogStash::Filters::LookUp < LogStash::Filters::Base
  config_name "lookup"
  # The name of the logstash event field containing the value to be compared for a
  # match by the map filter (e.g. `message`, `host`, `response_code`). 
  # 
  # If this field is an array, only the first value will be used.
  config :fields, :validate => :array, :required => true

  # By default false, if false, then all the result will be stored into a field called lookup_result
  # If true, the same field used to lookup, will be replaced.
  config :override, :validate => :boolean, :default => false

  # Can be webservice or file
  config :type, :validate => :string, :default => 'webservice'

  # Path of a file
  config :path, :validate => :string

  config :format, :validate => :string, :default => 'yml'

  config :headers, :validate => :hash, :default => {  }
  config :params, :validate => :hash, :default => {  }

  #default field where store results if override option is false
  config :result_key, :validate => :string, :default => "lookup_result"

  # The full URI path of a Web service who generates an JSON, yml or CSV format response.
  # requires to append as suffix the format type. Ex: http://localhost:8080/geoPoints?type=json
  # http://localhost:8080/geoPoints/json
  # http://localhost:8080/geoPoints/csv
  # If no suffix matches, defaults to YAML
  config :url, :validate => :string

  #HTTP method
  config :method, :validate => :string, :default => "get"



  # When using a map file or url, this setting will indicate how frequently
  # (in seconds) logstash will check the YAML file or url for updates.
  config :refresh_interval, :validate => :number, :default => 300

  # In case no mapping occurs in the event (no matches), this will add a default
  # mapping string, which will always populate `field`, if the match failed.
  config :default_values, :validate => :array, :default => {}

  def get_map
    @my_map
  end

  def fill_map(data)
    get_map.merge!(data)
  end

  public
  def register
    @my_map = {}
    @next_refresh = Time.now + @refresh_interval
    load(true)
    @logger.debug? and @logger.debug("#{self.class.name}: map - ", :map => get_map)
    type = 'Exact'
    @logger.debug? and @logger.debug("#{self.class.name}: map mapping method - "+type)
  end

  # def register

  def json_loader(data)
    fill_map(JSON.parse(data))
  end

  def csv_loader(data)
    data = CSV.parse(data).inject(Hash.new) do |acc, v|
      acc[v[0]] = v[1]
      acc
    end
    fill_map(data)
  end

  def yml_loader(data)
    fill_map(YAML.load(data))
  end

  def load_data(registering, data)
    begin
      if @format.eql?('json')
        return json_loader(data)
      elsif @format.eql?('csv')
        return csv_loader(data)
      end
      yml_loader(data)
    rescue Exception => _
      if registering
        raise "#{self.class.name}: Bad Syntax in data #{data}"
      else
        @logger.warn("#{self.class.name}: Bad Syntax in map file, continuing with old map", :map_path => data)
      end
    end
  end

  def load(registering=false)
    begin
      if @type=='webservice'
        route = @url
        data = get_webservice_content(route)
      elsif @type=='file'
        route = @path
        data = get_file_content(route)
      end
      load_data(registering, data)
    rescue Exception => _
      if registering
        raise "#{self.class.name}: Failed to initialize with type #{type} and route #{route}"
      end
      @logger.warn("#{self.class.name}: Something happened with load. Continuing with old map", :type => @type, :route => route)
    end
  end

  # def load

  def get_file_content(file)
    data = ''
    File.open(file, 'r') do |read_file|
      data +=read_file.read
    end
    data
  end

  # def get_file_content

  def get_webservice_content(path)
    case @method
      when "get"
        data = RestClient.get sprint(path), sprint(@headers)
      when "post"
        data = RestClient.post sprint(path), sprint(@params), sprint(@headers)
    end
    data
  end

  # def get_webservice_content

  def sprint(hash)
    hash
  end

  public
  def filter(event)
    if @next_refresh < Time.now
      load()
      @next_refresh = Time.now + @refresh_interval
      @logger.info('downloading and refreshing map file')
    end
    begin
      matched = true
      if @override
        result = event;
      else
        event[@result_key] = {}
        result = event[@result_key]
      end
      @fields.each { |key|
        key_string = key.to_s
        if event.include?(key_string)
          val_string = event[key_string]
          if get_map.include?(val_string)
            result[key_string] = get_map[val_string]
          else
            if @default_values and @default_values.include?(key_string)
              result[key_string] = event.sprintf(@default_values[key_string])
            end
            matched = false
          end
        end
      }
      filter_matched(event) if matched and result.length == @fields.length
    rescue Exception => e
      @logger.error('Something went wrong when attempting to map from my_map', :exception => e, :field => @fields, :event => event)
    end
  end # def filter
end # class LogStash::Filters::LookUp
